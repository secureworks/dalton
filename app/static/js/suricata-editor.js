/*
 * Optional CodeMirror-backed editor for the custom-rules textarea on the
 * Suricata coverage page. Off by default; the plain textarea is the
 * fallback and the default experience.
 */
(function () {
  "use strict";

  var STORAGE_KEY = "dalton_suricata_rule_editor_enabled";
  var ENGINE_ANALYSIS_STORAGE_KEY = "dalton_suricata_engine_analysis_enabled";
  var KEYWORDS_URL = "/dalton/controller_api/rule_keywords";
  var CHECK_URL = "/dalton/controller_api/check_rules";
  // Each check spawns a fresh suricata-language-server process on the linter
  // (see dalton-agent/linter/app.py) rather than reusing an in-process
  // instance, so it costs noticeably more than a bare HTTP round trip --
  // ~0.6-0.9s measured in dev testing, regardless of rule count, since
  // interpreter/subprocess startup dominates. The in-flight guard below
  // also caps each browser at one outstanding request, so this can stay
  // short without putting a room full of people through a request per
  // keystroke.
  var CHECK_DEBOUNCE_MS = 1500;
  // Info and Hint are collapsed into one "note" level. Engine analysis is on
  // by default and nearly everything it reports is a Hint; the LSP distinction
  // between the two is invisible to anyone who does not already know the
  // scale, and "hint" reads as advice being withheld rather than as a fact
  // being reported.
  var SEVERITY = {
    1: { cm: "error", label: "error", cls: "suri-diag-error" },
    2: { cm: "warning", label: "warning", cls: "suri-diag-warning" },
    3: { cm: "note", label: "note", cls: "suri-diag-note" },
    4: { cm: "note", label: "note", cls: "suri-diag-note" },
  };
  // Emitted once per rule by engine analysis; a classification, not
  // something to act on, and at one line per rule it buries everything
  // else. Filtered on the client so the linter stays a faithful proxy for
  // what the language server said.
  var FILTERED_MESSAGE_PATTERN = /^Rule type is /;
  var cm = null;
  var keywordsByName = null; // null until the first fetch resolves
  var hoverTooltip = null;
  var latestLintResults = []; // CodeMirror lint addon delivers this synchronously
  var checkDebounceTimer = null;
  var checkInFlight = false;
  // A check asked for while one is in flight used to be dropped with nothing
  // to re-arm it, so toggling engine analysis or hitting the button at the
  // wrong moment left the panel showing results for the previous settings
  // until the next edit. Remember that one was wanted and run it on release.
  var checkPending = false;
  var hoverTimer = null;
  var HOVER_DELAY_MS = 350;
  // Nothing else bounds the browser -> controller leg, and the browser default
  // is minutes; a stall would pin checkInFlight and kill checking until reload.
  var REQUEST_TIMEOUT_MS = 8000;
  // fetchKeywords() and runCheck() both fire from enableEditor() and both
  // report through the same status line; without this, whichever request
  // happens to resolve second wins the race and can stomp the other's
  // text. runCheck() always starts first (it's called synchronously right
  // after fetchKeywords() kicks off its fetch), so setting this before
  // runCheck's own fetch goes out - not when it resolves - closes the race
  // regardless of which response comes back first: fetchKeywords checks it
  // right before every status update and steps aside once a check is
  // underway, since the check status is the more current, more complete
  // answer (it includes the engine version too).
  var hasCheckResult = false;
  // Bumped whenever the editor is torn down. A check already in flight then
  // lands on a page that has moved on: disableEditor() has cleared the panel,
  // so an unguarded response would refill it and those findings would still be
  // there next time the editor was switched on, describing text that may have
  // changed since. A token rather than a null check on cm, because a disable
  // followed by an enable inside one request's lifetime leaves an editor that
  // exists but is not the one that asked.
  var checkGeneration = 0;

  CodeMirror.defineSimpleMode("suricata", {
    start: [
      { regex: /#.*/, token: "comment" },
      {
        regex: /\b(?:alert|pass|drop|reject|rejectsrc|rejectdst|rejectboth|log)\b/,
        token: "keyword",
        next: "header",
      },
    ],
    header: [
      { regex: /"(?:[^\\"]|\\.)*"/, token: "string" },
      { regex: /\$[A-Z_][A-Z0-9_]*/, token: "variable-2" },
      { regex: /->|<>/, token: "operator" },
      { regex: /\(/, token: "bracket", next: "options" },
      { regex: /[^\s()]+/, token: "atom" },
    ],
    options: [
      { regex: /#.*/, token: "comment" },
      { regex: /"(?:[^\\"]|\\.)*"/, token: "string" },
      // A string still being typed (no closing quote yet on this line) is a
      // string too, so completion stays quiet inside a half-written msg or
      // content value rather than offering keywords in the middle of it.
      { regex: /"(?:[^\\"]|\\.)*$/, token: "string" },
      // Any word immediately followed by ':' or ';' is treated as an option
      // name, rather than matching against an enumerated keyword list, so
      // keywords the completion data has never heard of still colour
      // correctly.
      { regex: /[a-zA-Z_][\w.]*(?=\s*[:;])/, token: "attribute" },
      { regex: /;/, token: "operator" },
      { regex: /\)/, token: "bracket", next: "start" },
      { regex: /[^\s;)"]+/, token: null },
    ],
    meta: { lineComment: "#" },
  });

  function readStoredPreference() {
    try {
      return window.localStorage.getItem(STORAGE_KEY) === "true";
    } catch (e) {
      return false;
    }
  }

  function writeStoredPreference(enabled) {
    try {
      window.localStorage.setItem(STORAGE_KEY, enabled ? "true" : "false");
    } catch (e) {
      // localStorage unavailable (e.g. private browsing) - preference just
      // won't persist across reloads.
    }
  }

  function setStatus(text, className) {
    var status = document.getElementById("ruleEditorStatus");
    if (status) {
      status.className = className || "";
      status.textContent = text || "";
    }
  }

  function fetchKeywords() {
    fetch(KEYWORDS_URL, { headers: { Accept: "application/json" } })
      .then(function (resp) {
        return resp.json();
      })
      .then(function (data) {
        if (!data.available || !data.keywords) {
          // Fall back to whatever was already loaded (possibly nothing)
          // rather than showing an empty completion popup.
          if (!keywordsByName && !hasCheckResult) {
            setStatus("");
          }
          return;
        }
        keywordsByName = {};
        data.keywords.forEach(function (kw) {
          keywordsByName[kw.name] = kw;
        });
        if (hasCheckResult) {
          return;
        }
        var status = "keywords from Suricata " + data.engine_version;
        if (data.stale) {
          status += " (cached; linter unavailable)";
        }
        setStatus(status);
      })
      .catch(function () {
        if (!keywordsByName && !hasCheckResult) {
          setStatus("");
        }
      });
  }

  // Word immediately before the cursor, matching how the mode tokenizes
  // option names (letters/digits/underscore/dot).
  function currentWordRange(cm, cursor) {
    var line = cm.getLine(cursor.line);
    var start = cursor.ch;
    var end = cursor.ch;
    while (start > 0 && /[\w.]/.test(line.charAt(start - 1))) {
      start--;
    }
    while (end < line.length && /[\w.]/.test(line.charAt(end))) {
      end++;
    }
    return {
      text: line.slice(start, end),
      from: CodeMirror.Pos(cursor.line, start),
      to: CodeMirror.Pos(cursor.line, end),
    };
  }

  // Rule options live between the header's parens. Completing outside them
  // offers option keywords where only an action, protocol, address or port is
  // legal, which fights the user on every line. Ask the mode rather than
  // scanning the line for parens: a scan sees the ')' inside a pcre or
  // content string and gives up on the rest of that rule, and it never
  // recognises the continuation lines of a multi-line rule at all. The
  // simple-mode state carries across lines and skips over strings, so it
  // knows where it is in both cases. A cursor inside a string is not a
  // keyword position either, whatever state the mode is in.
  function inOptions(cm, cursor) {
    var token = cm.getTokenAt(cursor);
    if (token.type === "string") {
      return false;
    }
    return !!(token.state && token.state.state === "options");
  }

  function suricataHint(cm) {
    if (!keywordsByName) {
      return null;
    }
    var cursor = cm.getCursor();
    if (!inOptions(cm, cursor)) {
      return null;
    }
    var word = currentWordRange(cm, cursor);
    var prefix = word.text.toLowerCase();
    // Without a prefix this would drop the entire keyword list -- several
    // hundred entries -- into the popup, which is no help to anyone.
    if (!prefix) {
      return null;
    }
    var matches = Object.keys(keywordsByName)
      .filter(function (name) {
        return name.toLowerCase().indexOf(prefix) === 0;
      })
      .sort()
      .map(function (name) {
        var kw = keywordsByName[name];
        var display = kw.legacy_for ? name + " (legacy for " + kw.legacy_for + ")" : name;
        return { text: name, displayText: display };
      });
    if (matches.length === 0) {
      return null;
    }
    return { list: matches, from: word.from, to: word.to };
  }

  function hideHoverTooltip() {
    if (hoverTimer) {
      clearTimeout(hoverTimer);
      hoverTimer = null;
    }
    if (hoverTooltip) {
      hoverTooltip.remove();
      hoverTooltip = null;
    }
  }

  function showHoverTooltip(cm, pos, coords, kw) {
    hideHoverTooltip();
    var el = document.createElement("div");
    el.className = "suricata-editor-tooltip";
    el.style.cssText =
      "position:absolute;z-index:10;max-width:420px;padding:6px 10px;" +
      "background:#333;color:#fff;font-size:12px;border-radius:3px;" +
      "box-shadow:0 1px 4px rgba(0,0,0,0.4);";
    // kw.description already notes "(legacy name for 'X')" for aliases -
    // see legacy_keywords.py - so nothing to add here.
    el.textContent = kw.description || "";
    if (kw.documentation) {
      el.appendChild(document.createElement("br"));
      var link = document.createElement("a");
      link.href = kw.documentation;
      link.target = "_blank";
      link.rel = "noopener noreferrer";
      link.style.color = "#9cf";
      link.textContent = kw.documentation;
      el.appendChild(link);
    }
    document.body.appendChild(el);
    // coords is in "page" mode (document-relative, scroll already baked
    // in) since position:absolute here is relative to the document too.
    el.style.left = coords.right + 8 + "px";
    el.style.top = coords.top + "px";
    hoverTooltip = el;
  }

  function onEditorMouseOver(cm, event) {
    if (!keywordsByName) {
      return;
    }
    var pos = cm.coordsChar(
      { left: event.clientX, top: event.clientY },
      "window"
    );
    var token = cm.getTokenAt(pos);
    if (token.type !== "attribute") {
      hideHoverTooltip();
      return;
    }
    var kw = keywordsByName[token.string];
    if (!kw) {
      hideHoverTooltip();
      return;
    }
    showHoverTooltip(cm, pos, cm.charCoords(pos, "page"), kw);
  }

  function readEngineAnalysisPreference() {
    try {
      var stored = window.localStorage.getItem(ENGINE_ANALYSIS_STORAGE_KEY);
      return stored === null ? true : stored === "true";
    } catch (e) {
      return true;
    }
  }

  function writeEngineAnalysisPreference(enabled) {
    try {
      window.localStorage.setItem(
        ENGINE_ANALYSIS_STORAGE_KEY,
        enabled ? "true" : "false"
      );
    } catch (e) {
      // localStorage unavailable - preference just won't persist
    }
  }

  // The lint addon's severity is a free-form string: it concatenates it into
  // CodeMirror-lint-marker-<severity> and friends. Its own stylesheet ships
  // icons for "error" and "warning" only, so mapping notes onto "warning" --
  // the obvious way to avoid a blank 16px gutter -- put a warning triangle
  // beside messages that are not warnings. suricata-editor.css supplies the
  // "note" icon instead.
  function lspSeverityToCmSeverity(severity) {
    return (SEVERITY[severity] || SEVERITY[2]).cm;
  }

  // Suricata can emit the same note more than once for one rule: engine
  // analysis runs a fast-pattern pass and a rule pass, and both append to the
  // same record, so e.g. the 'fast_pattern:only' note arrives twice. Nothing is
  // gained by showing it twice.
  function dedupe(diags) {
    var seen = {};
    return diags.filter(function (d) {
      var line = d.range && d.range.start ? d.range.start.line : 0;
      var key = line + "\u0000" + d.severity + "\u0000" + d.message;
      if (seen[key]) {
        return false;
      }
      seen[key] = true;
      return true;
    });
  }

  // Severity first, line second. Sorting by line kept the panel aligned with
  // the editor, but it put an error in the fortieth rule below thirty-nine
  // notes -- and the panel is a fixed height that scrolls, so "1 error" in the
  // status line could point at a row that was not on screen. Each row carries
  // its line number as a link, so ordering is not what makes a finding
  // reachable.
  //
  // Rank rather than raw severity: Information and Hint render identically as
  // notes, so sorting on the LSP value would order two visually identical rows
  // by a distinction the reader cannot see, and break line order between them
  // for no visible reason.
  function severityRank(severity) {
    var value = severity || 2;
    return value >= 3 ? 3 : value;
  }

  function sortDiagnostics(diags) {
    return diags.slice().sort(function (a, b) {
      var ra = severityRank(a.severity);
      var rb = severityRank(b.severity);
      if (ra !== rb) {
        return ra - rb;
      }
      var la = a.range && a.range.start ? a.range.start.line : 0;
      var lb = b.range && b.range.start ? b.range.start.line : 0;
      return la - lb;
    });
  }

  function summarise(diags) {
    if (!diags.length) {
      return "No problems found.";
    }
    var counts = { 1: 0, 2: 0, 3: 0, 4: 0 };
    diags.forEach(function (d) {
      counts[SEVERITY[d.severity] ? d.severity : 2] += 1;
    });
    var parts = [];
    if (counts[1]) {
      parts.push(counts[1] + (counts[1] === 1 ? " error" : " errors"));
    }
    if (counts[2]) {
      parts.push(counts[2] + (counts[2] === 1 ? " warning" : " warnings"));
    }
    var notes = counts[3] + counts[4];
    if (notes) {
      parts.push(notes + (notes === 1 ? " note" : " notes"));
    }
    return parts.join(", ") + ".";
  }

  function clearResults() {
    var panel = document.getElementById("ruleEditorResults");
    if (panel) {
      panel.innerHTML = "";
    }
  }

  // The gutter markers alone can only show one problem at a time, need to be
  // discovered by hovering, and say nothing on touch. The list gives the whole
  // picture at once and somewhere to click through to a line.
  function renderResults(diags) {
    var panel = document.getElementById("ruleEditorResults");
    if (!panel) {
      return;
    }
    panel.innerHTML = "";
    if (!diags.length) {
      return;
    }
    var list = document.createElement("ul");
    list.className = "suri-diag-list";
    diags.forEach(function (diag) {
      var severity = SEVERITY[diag.severity] || SEVERITY[2];
      var line = (diag.range && diag.range.start ? diag.range.start.line : 0) + 1;

      var item = document.createElement("li");
      item.className = severity.cls;

      var sev = document.createElement("span");
      sev.className = "suri-diag-sev";
      sev.textContent = severity.label;
      item.appendChild(sev);

      var jump = document.createElement("a");
      jump.className = "suri-diag-line";
      jump.href = "#";
      jump.textContent = "line " + line;
      jump.addEventListener("click", function (event) {
        event.preventDefault();
        if (cm) {
          cm.setCursor({ line: line - 1, ch: 0 });
          cm.focus();
        }
      });
      item.appendChild(jump);

      var message = document.createElement("span");
      message.className = "suri-diag-msg";
      message.textContent = diag.message;
      item.appendChild(message);

      list.appendChild(item);
    });
    panel.appendChild(list);
  }

  function diagnosticToLintError(diag) {
    return {
      from: CodeMirror.Pos(diag.range.start.line, diag.range.start.character),
      to: CodeMirror.Pos(diag.range.end.line, diag.range.end.character),
      message: diag.message,
      severity: lspSeverityToCmSeverity(diag.severity),
    };
  }

  // Fails open in every direction: a checker that is down, slow or confused
  // leaves the editor fully usable and never blocks submission. It must say so
  // rather than just clearing, though -- silently showing nothing is
  // indistinguishable from "your rules are clean", which is the one conclusion
  // a broken checker must not let anyone draw.
  function runCheck() {
    if (!cm) {
      return;
    }
    if (checkInFlight) {
      checkPending = true;
      return;
    }
    var rules = cm.getValue();
    if (!rules.trim()) {
      // Nothing to check, so nothing to say. hasCheckResult stays as it was:
      // setting it here would silence fetchKeywords()'s status line for good
      // on the common case of enabling the editor over an empty box.
      latestLintResults = [];
      clearResults();
      setStatus("");
      cm.performLint();
      return;
    }
    // Set before anything async happens - see the comment on
    // hasCheckResult's declaration for why this, not the fetch resolving,
    // is what closes the race with fetchKeywords().
    hasCheckResult = true;

    var engineAnalysisCheckbox = document.getElementById("optionEngineAnalysis");
    var engineAnalysis = engineAnalysisCheckbox
      ? engineAnalysisCheckbox.checked
      : false;

    checkInFlight = true;
    var generation = checkGeneration;
    setStatus("Checking\u2026", "suri-check-busy");

    // The editor this check was started for is gone or has been replaced.
    function superseded() {
      return generation !== checkGeneration || !cm;
    }

    function unavailable() {
      if (superseded()) {
        return;
      }
      latestLintResults = [];
      clearResults();
      setStatus("Syntax checking is unavailable right now.", "suri-check-unavailable");
      if (cm) {
        cm.performLint();
      }
    }

    var controller = new AbortController();
    var timer = setTimeout(function () {
      controller.abort();
    }, REQUEST_TIMEOUT_MS);

    fetch(CHECK_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ rules: rules, engine_analysis: engineAnalysis }),
      signal: controller.signal,
    })
      .then(function (resp) {
        return resp.json();
      })
      .then(function (data) {
        if (superseded()) {
          return;
        }
        if (!data || !data.available) {
          unavailable();
          return;
        }
        var diags = sortDiagnostics(
          dedupe(
            (data.diagnostics || []).filter(function (d) {
              return !FILTERED_MESSAGE_PATTERN.test(d.message);
            })
          )
        );
        latestLintResults = diags.map(diagnosticToLintError);
        renderResults(diags);
        setStatus(
          summarise(diags) +
            (data.engine_version ? " (Suricata " + data.engine_version + ")" : ""),
          diags.length ? "suri-check-found" : "suri-check-clean"
        );
        if (cm) {
          cm.performLint();
        }
      })
      .catch(unavailable)
      // finally, not then: if unavailable() itself throws, a .then(onFulfilled)
      // is skipped and the guard leaks, which kills checking for good.
      .finally(function () {
        clearTimeout(timer);
        checkInFlight = false;
        if (checkPending) {
          checkPending = false;
          runCheck();
        }
      });
  }

  function scheduleCheck() {
    if (checkDebounceTimer) {
      clearTimeout(checkDebounceTimer);
    }
    checkDebounceTimer = setTimeout(runCheck, CHECK_DEBOUNCE_MS);
  }

  // The lint addon's async mode aborts a pending result on any document
  // change (it registers its own "change" listener that bumps a
  // "waitingFor" id and drops anything that resolves after). Stashing the
  // updateLinting callback from getAnnotations and calling it whenever the
  // fetch above resolves would therefore deliver nothing, silently, the
  // request succeeds and the diagnostics are correct but nothing ever
  // renders. Instead: keep results in latestLintResults, have
  // getAnnotations deliver them synchronously every time CodeMirror asks,
  // and call cm.performLint() to trigger a fresh ask once a fetch
  // completes.
  function getAnnotations(text, updateLinting) {
    updateLinting(latestLintResults);
  }

  // The check button, engine-analysis toggle, status and results only mean
  // anything while the editor is up.
  function updateControlsVisibility(visible) {
    var controls = document.getElementById("ruleEditorControls");
    if (controls) {
      controls.style.display = visible ? "" : "none";
    }
  }

  function enableEditor() {
    if (cm) {
      return;
    }
    var textarea = document.querySelector('textarea[name="custom_ruleset"]');
    if (!textarea) {
      return;
    }
    latestLintResults = [];
    cm = CodeMirror.fromTextArea(textarea, {
      mode: "suricata",
      lineNumbers: true,
      lineWrapping: true,
      viewportMargin: Infinity,
      extraKeys: { "Ctrl-Space": "autocomplete" },
      hintOptions: { hint: suricataHint, completeSingle: false },
      gutters: ["CodeMirror-lint-markers"],
      lint: {
        async: true,
        lintOnChange: false,
        getAnnotations: getAnnotations,
      },
    });
    cm.getWrapperElement().addEventListener("mousemove", function (event) {
      // onEditorMouseOver re-tokenises the line and rebuilds the tooltip, so
      // running it at pointer rate is a lot of work to do sixty times a second
      // while the pointer simply rests on a keyword.
      if (hoverTimer) {
        clearTimeout(hoverTimer);
      }
      var x = event.clientX;
      var y = event.clientY;
      hoverTimer = setTimeout(function () {
        onEditorMouseOver(cm, { clientX: x, clientY: y, target: null });
      }, HOVER_DELAY_MS);
    });
    cm.getWrapperElement().addEventListener("mouseleave", function (event) {
      // The tooltip lives on document.body, not inside the wrapper, so
      // moving the pointer onto it counts as leaving the editor. Without
      // this the tooltip is torn down before its link can be clicked.
      if (hoverTooltip && hoverTooltip.contains(event.relatedTarget)) {
        return;
      }
      hideHoverTooltip();
    });
    cm.on("changes", scheduleCheck);
    // Ctrl-Space alone is not a trigger anyone can rely on: on most Linux
    // desktops it is bound to the input-method switcher and never reaches the
    // browser, so completion looked simply broken. Offer it while typing, the
    // way an editor is expected to behave. suricataHint returns null when
    // there is nothing to say, so this is quiet when it should be.
    cm.on("inputRead", function (editor, change) {
      // change.text is an array of lines, so its length only rules out a
      // multi-line paste. Checking the line's own length is what separates a
      // typed character from a pasted rule -- otherwise pasting one drops a
      // completion popup over it.
      if (change.text.length !== 1 || change.text[0].length !== 1) {
        return;
      }
      if (!/[\w.]/.test(change.text[0])) {
        return;
      }
      editor.showHint();
    });
    if (!keywordsByName) {
      fetchKeywords();
    }

    var engineAnalysisCheckbox = document.getElementById("optionEngineAnalysis");
    if (engineAnalysisCheckbox) {
      engineAnalysisCheckbox.checked = readEngineAnalysisPreference();
    }
    updateControlsVisibility(true);
    runCheck();
  }

  function disableEditor() {
    if (!cm) {
      return;
    }
    if (checkDebounceTimer) {
      clearTimeout(checkDebounceTimer);
      checkDebounceTimer = null;
    }
    updateControlsVisibility(false);
    hideHoverTooltip();
    clearResults();
    setStatus("");
    latestLintResults = [];
    hasCheckResult = false;
    checkGeneration += 1;
    checkPending = false;
    cm.toTextArea();
    cm = null;
  }

  function setEnabled(enabled) {
    if (enabled) {
      enableEditor();
    } else {
      disableEditor();
    }
    writeStoredPreference(enabled);
  }

  // The custom-rules box lives in a <span> that gets shown/hidden by
  // coverage.html. CodeMirror measures itself incorrectly if it's
  // constructed or left sitting inside a hidden container - call this
  // whenever that span is revealed.
  function refresh() {
    if (cm) {
      cm.refresh();
    }
  }

  function init() {
    var checkbox = document.getElementById("optionRuleEditor");
    if (!checkbox) {
      return;
    }

    var enabled = readStoredPreference();
    checkbox.checked = enabled;
    // The template also hides these, but don't depend on that staying true.
    updateControlsVisibility(enabled);
    if (enabled) {
      enableEditor();
    }

    checkbox.addEventListener("change", function () {
      setEnabled(checkbox.checked);
    });

    var checkNow = document.getElementById("ruleEditorCheckNow");
    if (checkNow) {
      checkNow.addEventListener("click", function (event) {
        event.preventDefault();
        if (checkDebounceTimer) {
          clearTimeout(checkDebounceTimer);
          checkDebounceTimer = null;
        }
        runCheck();
      });
    }

    var engineAnalysisCheckbox = document.getElementById("optionEngineAnalysis");
    if (engineAnalysisCheckbox) {
      engineAnalysisCheckbox.addEventListener("change", function () {
        writeEngineAnalysisPreference(engineAnalysisCheckbox.checked);
        // The user just asked to see something different - re-run now
        // rather than waiting for the next edit.
        runCheck();
      });
    }
  }

  window.SuricataEditor = {
    init: init,
    refresh: refresh,
  };
})();
