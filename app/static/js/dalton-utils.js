/* dalton-utils.js — shared utilities for Dalton UI pages */
var DaltonUtils = (function () {

    function escapeHtml(text) {
        if (text === null || text === undefined) return '';
        var div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    function titleCase(str) {
        return str.charAt(0).toUpperCase() + str.slice(1).toLowerCase();
    }

    function formatTechnology(tech) {
        var tlist = tech.split('/');
        if (tlist.length > 1) {
            if (tlist[1].indexOf('rust_') === 0) {
                var version = tlist[1].substring(5);
                var extra = tlist.length > 2 ? tlist[2] + ' - ' : '';
                return titleCase(tlist[0]) + ' ' + version + ' (' + extra + 'with Rust support)';
            } else {
                var suffix = tlist.length > 2 ? ' (' + tlist[2] + ')' : '';
                return titleCase(tlist[0]) + ' ' + tlist[1] + suffix;
            }
        } else {
            return titleCase(tech);
        }
    }

    // createPoller(pollFn, interval)
    // Sets up interval-based polling and pauses/resumes on tab visibility.
    // Returns { start, stop }.
    function createPoller(pollFn, interval) {
        var timer = null;

        function start() {
            if (timer) clearInterval(timer);
            timer = setInterval(pollFn, interval);
        }

        function stop() {
            if (timer) {
                clearInterval(timer);
                timer = null;
            }
        }

        document.addEventListener('visibilitychange', function () {
            if (document.hidden) {
                stop();
            } else {
                pollFn();   // immediate refresh when tab becomes visible
                start();
            }
        });

        return { start: start, stop: stop };
    }

    // createLastUpdatedTracker(elementId)
    // Tracks when data was last refreshed and displays "Updated: Ns ago" in
    // the named element, updated every second.
    // Returns { markUpdated } — call this after each successful poll.
    function createLastUpdatedTracker(elementId) {
        var lastUpdateTime = new Date();

        function updateDisplay() {
            var el = document.getElementById(elementId);
            if (el) {
                var seconds = Math.floor((new Date() - lastUpdateTime) / 1000);
                el.textContent = 'Updated: ' + seconds + 's ago';
            }
        }

        setInterval(updateDisplay, 1000);

        function markUpdated() {
            lastUpdateTime = new Date();
            updateDisplay();
        }

        return { markUpdated: markUpdated };
    }

    return {
        escapeHtml: escapeHtml,
        titleCase: titleCase,
        formatTechnology: formatTechnology,
        createPoller: createPoller,
        createLastUpdatedTracker: createLastUpdatedTracker
    };
}());
