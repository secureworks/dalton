/*
  Highlight.js 10.3.2 (31e1fc40)
  License: BSD-3-Clause
  Copyright (c) 2006-2020, Ivan Sagalaev
*/
var hljs=function(){"use strict";function e(n){Object.freeze(n)
;var t="function"==typeof n
;return Object.getOwnPropertyNames(n).forEach((function(r){
!Object.hasOwnProperty.call(n,r)||null===n[r]||"object"!=typeof n[r]&&"function"!=typeof n[r]||t&&("caller"===r||"callee"===r||"arguments"===r)||Object.isFrozen(n[r])||e(n[r])
})),n}class n{constructor(e){void 0===e.data&&(e.data={}),this.data=e.data}
ignoreMatch(){this.ignore=!0}}function t(e){
return e.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;").replace(/'/g,"&#x27;")
}function r(e,...n){var t={};for(const n in e)t[n]=e[n]
;return n.forEach((function(e){for(const n in e)t[n]=e[n]})),t}function a(e){
return e.nodeName.toLowerCase()}var i=Object.freeze({__proto__:null,
escapeHTML:t,inherit:r,nodeStream:function(e){var n=[];return function e(t,r){
for(var i=t.firstChild;i;i=i.nextSibling)3===i.nodeType?r+=i.nodeValue.length:1===i.nodeType&&(n.push({
event:"start",offset:r,node:i}),r=e(i,r),a(i).match(/br|hr|img|input/)||n.push({
event:"stop",offset:r,node:i}));return r}(e,0),n},mergeStreams:function(e,n,r){
var i=0,s="",o=[];function l(){
return e.length&&n.length?e[0].offset!==n[0].offset?e[0].offset<n[0].offset?e:n:"start"===n[0].event?e:n:e.length?e:n
}function c(e){s+="<"+a(e)+[].map.call(e.attributes,(function(e){
return" "+e.nodeName+'="'+t(e.value)+'"'})).join("")+">"}function u(e){
s+="</"+a(e)+">"}function g(e){("start"===e.event?c:u)(e.node)}
for(;e.length||n.length;){var d=l()
;if(s+=t(r.substring(i,d[0].offset)),i=d[0].offset,d===e){o.reverse().forEach(u)
;do{g(d.splice(0,1)[0]),d=l()}while(d===e&&d.length&&d[0].offset===i)
;o.reverse().forEach(c)
}else"start"===d[0].event?o.push(d[0].node):o.pop(),g(d.splice(0,1)[0])}
return s+t(r.substr(i))}});const s=e=>!!e.kind;class o{constructor(e,n){
this.buffer="",this.classPrefix=n.classPrefix,e.walk(this)}addText(e){
this.buffer+=t(e)}openNode(e){if(!s(e))return;let n=e.kind
;e.sublanguage||(n=`${this.classPrefix}${n}`),this.span(n)}closeNode(e){
s(e)&&(this.buffer+="</span>")}value(){return this.buffer}span(e){
this.buffer+=`<span class="${e}">`}}class l{constructor(){this.rootNode={
children:[]},this.stack=[this.rootNode]}get top(){
return this.stack[this.stack.length-1]}get root(){return this.rootNode}add(e){
this.top.children.push(e)}openNode(e){const n={kind:e,children:[]}
;this.add(n),this.stack.push(n)}closeNode(){
if(this.stack.length>1)return this.stack.pop()}closeAllNodes(){
for(;this.closeNode(););}toJSON(){return JSON.stringify(this.rootNode,null,4)}
walk(e){return this.constructor._walk(e,this.rootNode)}static _walk(e,n){
return"string"==typeof n?e.addText(n):n.children&&(e.openNode(n),
n.children.forEach((n=>this._walk(e,n))),e.closeNode(n)),e}static _collapse(e){
"string"!=typeof e&&e.children&&(e.children.every((e=>"string"==typeof e))?e.children=[e.children.join("")]:e.children.forEach((e=>{
l._collapse(e)})))}}class c extends l{constructor(e){super(),this.options=e}
addKeyword(e,n){""!==e&&(this.openNode(n),this.addText(e),this.closeNode())}
addText(e){""!==e&&this.add(e)}addSublanguage(e,n){const t=e.root
;t.kind=n,t.sublanguage=!0,this.add(t)}toHTML(){
return new o(this,this.options).value()}finalize(){return!0}}function u(e){
return e?"string"==typeof e?e:e.source:null}
const g="[a-zA-Z]\\w*",d="[a-zA-Z_]\\w*",h="\\b\\d+(\\.\\d+)?",f="(-?)(\\b0[xX][a-fA-F0-9]+|(\\b\\d+(\\.\\d*)?|\\.\\d+)([eE][-+]?\\d+)?)",p="\\b(0b[01]+)",m={
begin:"\\\\[\\s\\S]",relevance:0},b={className:"string",begin:"'",end:"'",
illegal:"\\n",contains:[m]},v={className:"string",begin:'"',end:'"',
illegal:"\\n",contains:[m]},x={
begin:/\b(a|an|the|are|I'm|isn't|don't|doesn't|won't|but|just|should|pretty|simply|enough|gonna|going|wtf|so|such|will|you|your|they|like|more)\b/
},E=function(e,n,t={}){var a=r({className:"comment",begin:e,end:n,contains:[]
},t);return a.contains.push(x),a.contains.push({className:"doctag",
begin:"(?:TODO|FIXME|NOTE|BUG|OPTIMIZE|HACK|XXX):",relevance:0}),a
},_=E("//","$"),w=E("/\\*","\\*/"),N=E("#","$");var y=Object.freeze({
__proto__:null,IDENT_RE:g,UNDERSCORE_IDENT_RE:d,NUMBER_RE:h,C_NUMBER_RE:f,
BINARY_NUMBER_RE:p,
RE_STARTERS_RE:"!|!=|!==|%|%=|&|&&|&=|\\*|\\*=|\\+|\\+=|,|-|-=|/=|/|:|;|<<|<<=|<=|<|===|==|=|>>>=|>>=|>=|>>>|>>|>|\\?|\\[|\\{|\\(|\\^|\\^=|\\||\\|=|\\|\\||~",
SHEBANG:(e={})=>{const n=/^#![ ]*\//;return e.binary&&(e.begin=function(...e){
return e.map((e=>u(e))).join("")}(n,/.*\b/,e.binary,/\b.*/)),r({
className:"meta",begin:n,end:/$/,relevance:0,"on:begin":(e,n)=>{
0!==e.index&&n.ignoreMatch()}},e)},BACKSLASH_ESCAPE:m,APOS_STRING_MODE:b,
QUOTE_STRING_MODE:v,PHRASAL_WORDS_MODE:x,COMMENT:E,C_LINE_COMMENT_MODE:_,
C_BLOCK_COMMENT_MODE:w,HASH_COMMENT_MODE:N,NUMBER_MODE:{className:"number",
begin:h,relevance:0},C_NUMBER_MODE:{className:"number",begin:f,relevance:0},
BINARY_NUMBER_MODE:{className:"number",begin:p,relevance:0},CSS_NUMBER_MODE:{
className:"number",
begin:h+"(%|em|ex|ch|rem|vw|vh|vmin|vmax|cm|mm|in|pt|pc|px|deg|grad|rad|turn|s|ms|Hz|kHz|dpi|dpcm|dppx)?",
relevance:0},REGEXP_MODE:{begin:/(?=\/[^/\n]*\/)/,contains:[{className:"regexp",
begin:/\//,end:/\/[gimuy]*/,illegal:/\n/,contains:[m,{begin:/\[/,end:/\]/,
relevance:0,contains:[m]}]}]},TITLE_MODE:{className:"title",begin:g,relevance:0
},UNDERSCORE_TITLE_MODE:{className:"title",begin:d,relevance:0},METHOD_GUARD:{
begin:"\\.\\s*[a-zA-Z_]\\w*",relevance:0},END_SAME_AS_BEGIN:function(e){
return Object.assign(e,{"on:begin":(e,n)=>{n.data._beginMatch=e[1]},
"on:end":(e,n)=>{n.data._beginMatch!==e[1]&&n.ignoreMatch()}})}
}),R="of and for in not or if then".split(" ");function k(e){function n(n,t){
return RegExp(u(n),"m"+(e.case_insensitive?"i":"")+(t?"g":""))}class t{
constructor(){
this.matchIndexes={},this.regexes=[],this.matchAt=1,this.position=0}
addRule(e,n){
n.position=this.position++,this.matchIndexes[this.matchAt]=n,this.regexes.push([n,e]),
this.matchAt+=function(e){return RegExp(e.toString()+"|").exec("").length-1
}(e)+1}compile(){0===this.regexes.length&&(this.exec=()=>null)
;const e=this.regexes.map((e=>e[1]));this.matcherRe=n(function(e,n="|"){
for(var t=/\[(?:[^\\\]]|\\.)*\]|\(\??|\\([1-9][0-9]*)|\\./,r=0,a="",i=0;i<e.length;i++){
var s=r+=1,o=u(e[i]);for(i>0&&(a+=n),a+="(";o.length>0;){var l=t.exec(o)
;if(null==l){a+=o;break}
a+=o.substring(0,l.index),o=o.substring(l.index+l[0].length),
"\\"===l[0][0]&&l[1]?a+="\\"+(Number(l[1])+s):(a+=l[0],"("===l[0]&&r++)}a+=")"}
return a}(e),!0),this.lastIndex=0}exec(e){
this.matcherRe.lastIndex=this.lastIndex;const n=this.matcherRe.exec(e)
;if(!n)return null
;const t=n.findIndex(((e,n)=>n>0&&void 0!==e)),r=this.matchIndexes[t]
;return n.splice(0,t),Object.assign(n,r)}}class a{constructor(){
this.rules=[],this.multiRegexes=[],
this.count=0,this.lastIndex=0,this.regexIndex=0}getMatcher(e){
if(this.multiRegexes[e])return this.multiRegexes[e];const n=new t
;return this.rules.slice(e).forEach((([e,t])=>n.addRule(e,t))),
n.compile(),this.multiRegexes[e]=n,n}resumingScanAtSamePosition(){
return 0!==this.regexIndex}considerAll(){this.regexIndex=0}addRule(e,n){
this.rules.push([e,n]),"begin"===n.type&&this.count++}exec(e){
const n=this.getMatcher(this.regexIndex);n.lastIndex=this.lastIndex
;let t=n.exec(e)
;if(this.resumingScanAtSamePosition())if(t&&t.index===this.lastIndex);else{
const n=this.getMatcher(0);n.lastIndex=this.lastIndex+1,t=n.exec(e)}
return t&&(this.regexIndex+=t.position+1,
this.regexIndex===this.count&&this.considerAll()),t}}function i(e,n){
const t=e.input[e.index-1],r=e.input[e.index+e[0].length]
;"."!==t&&"."!==r||n.ignoreMatch()}
if(e.contains&&e.contains.includes("self"))throw Error("ERR: contains `self` is not supported at the top-level of a language.  See documentation.")
;return function t(s,o){const l=s;if(s.compiled)return l
;s.compiled=!0,s.__beforeBegin=null,s.keywords=s.keywords||s.beginKeywords
;let c=null
;if("object"==typeof s.keywords&&(c=s.keywords.$pattern,delete s.keywords.$pattern),
s.keywords&&(s.keywords=function(e,n){var t={}
;return"string"==typeof e?r("keyword",e):Object.keys(e).forEach((function(n){
r(n,e[n])})),t;function r(e,r){
n&&(r=r.toLowerCase()),r.split(" ").forEach((function(n){var r=n.split("|")
;t[r[0]]=[e,O(r[0],r[1])]}))}
}(s.keywords,e.case_insensitive)),s.lexemes&&c)throw Error("ERR: Prefer `keywords.$pattern` to `mode.lexemes`, BOTH are not allowed. (see mode reference) ")
;return l.keywordPatternRe=n(s.lexemes||c||/\w+/,!0),
o&&(s.beginKeywords&&(s.begin="\\b("+s.beginKeywords.split(" ").join("|")+")(?=\\b|\\s)",
s.__beforeBegin=i),
s.begin||(s.begin=/\B|\b/),l.beginRe=n(s.begin),s.endSameAsBegin&&(s.end=s.begin),
s.end||s.endsWithParent||(s.end=/\B|\b/),
s.end&&(l.endRe=n(s.end)),l.terminator_end=u(s.end)||"",
s.endsWithParent&&o.terminator_end&&(l.terminator_end+=(s.end?"|":"")+o.terminator_end)),
s.illegal&&(l.illegalRe=n(s.illegal)),
void 0===s.relevance&&(s.relevance=1),s.contains||(s.contains=[]),
s.contains=[].concat(...s.contains.map((function(e){return function(e){
return e.variants&&!e.cached_variants&&(e.cached_variants=e.variants.map((function(n){
return r(e,{variants:null},n)}))),e.cached_variants?e.cached_variants:M(e)?r(e,{
starts:e.starts?r(e.starts):null}):Object.isFrozen(e)?r(e):e}("self"===e?s:e)
}))),s.contains.forEach((function(e){t(e,l)
})),s.starts&&t(s.starts,o),l.matcher=function(e){const n=new a
;return e.contains.forEach((e=>n.addRule(e.begin,{rule:e,type:"begin"
}))),e.terminator_end&&n.addRule(e.terminator_end,{type:"end"
}),e.illegal&&n.addRule(e.illegal,{type:"illegal"}),n}(l),l}(e)}function M(e){
return!!e&&(e.endsWithParent||M(e.starts))}function O(e,n){
return n?Number(n):function(e){return R.includes(e.toLowerCase())}(e)?0:1}
const L={props:["language","code","autodetect"],data:function(){return{
detectedLanguage:"",unknownLanguage:!1}},computed:{className(){
return this.unknownLanguage?"":"hljs "+this.detectedLanguage},highlighted(){
if(!this.autoDetect&&!hljs.getLanguage(this.language))return console.warn(`The language "${this.language}" you specified could not be found.`),
this.unknownLanguage=!0,t(this.code);let e
;return this.autoDetect?(e=hljs.highlightAuto(this.code),
this.detectedLanguage=e.language):(e=hljs.highlight(this.language,this.code,this.ignoreIllegals),
this.detectectLanguage=this.language),e.value},autoDetect(){
return!(this.language&&(e=this.autodetect,!e&&""!==e));var e},
ignoreIllegals:()=>!0},render(e){return e("pre",{},[e("code",{
class:this.className,domProps:{innerHTML:this.highlighted}})])}},j={install(e){
e.component("highlightjs",L)}
},I=t,T=r,{nodeStream:S,mergeStreams:A}=i,B=Symbol("nomatch")
;return function(t){
var r=[],a=Object.create(null),i=Object.create(null),s=[],o=!0,l=/(^(<[^>]+>|\t|)+|\n)/gm,u="Could not find the language '{}', did you forget to load/include a language module?"
;const g={disableAutodetect:!0,name:"Plain text",contains:[]};var d={
noHighlightRe:/^(no-?highlight)$/i,
languageDetectRe:/\blang(?:uage)?-([\w-]+)\b/i,classPrefix:"hljs-",
tabReplace:null,useBR:!1,languages:null,__emitter:c};function h(e){
return d.noHighlightRe.test(e)}function f(e,n,t,r){var a={code:n,language:e}
;N("before:highlight",a);var i=a.result?a.result:p(a.language,a.code,t,r)
;return i.code=a.code,N("after:highlight",i),i}function p(e,t,r,i){var s=t
;function l(e,n){var t=_.case_insensitive?n[0].toLowerCase():n[0]
;return Object.prototype.hasOwnProperty.call(e.keywords,t)&&e.keywords[t]}
function c(){null!=y.subLanguage?function(){if(""!==O){var e=null
;if("string"==typeof y.subLanguage){
if(!a[y.subLanguage])return void M.addText(O)
;e=p(y.subLanguage,O,!0,R[y.subLanguage]),R[y.subLanguage]=e.top
}else e=m(O,y.subLanguage.length?y.subLanguage:null)
;y.relevance>0&&(L+=e.relevance),M.addSublanguage(e.emitter,e.language)}
}():function(){if(!y.keywords)return void M.addText(O);let e=0
;y.keywordPatternRe.lastIndex=0;let n=y.keywordPatternRe.exec(O),t="";for(;n;){
t+=O.substring(e,n.index);const r=l(y,n);if(r){const[e,a]=r
;M.addText(t),t="",L+=a,M.addKeyword(n[0],e)}else t+=n[0]
;e=y.keywordPatternRe.lastIndex,n=y.keywordPatternRe.exec(O)}
t+=O.substr(e),M.addText(t)}(),O=""}function g(e){
return e.className&&M.openNode(e.className),y=Object.create(e,{parent:{value:y}
})}function h(e,t,r){let a=function(e,n){var t=e&&e.exec(n)
;return t&&0===t.index}(e.endRe,r);if(a){if(e["on:end"]){const r=new n(e)
;e["on:end"](t,r),r.ignore&&(a=!1)}if(a){for(;e.endsParent&&e.parent;)e=e.parent
;return e}}if(e.endsWithParent)return h(e.parent,t,r)}function f(e){
return 0===y.matcher.regexIndex?(O+=e[0],1):(S=!0,0)}function b(e){
var n=e[0],t=s.substr(e.index),r=h(y,e,t);if(!r)return B;var a=y
;a.skip?O+=n:(a.returnEnd||a.excludeEnd||(O+=n),c(),a.excludeEnd&&(O=n));do{
y.className&&M.closeNode(),y.skip||y.subLanguage||(L+=y.relevance),y=y.parent
}while(y!==r.parent)
;return r.starts&&(r.endSameAsBegin&&(r.starts.endRe=r.endRe),
g(r.starts)),a.returnEnd?0:n.length}var v={};function x(t,a){var i=a&&a[0]
;if(O+=t,null==i)return c(),0
;if("begin"===v.type&&"end"===a.type&&v.index===a.index&&""===i){
if(O+=s.slice(a.index,a.index+1),!o){const n=Error("0 width match regex")
;throw n.languageName=e,n.badRule=v.rule,n}return 1}
if(v=a,"begin"===a.type)return function(e){var t=e[0],r=e.rule
;const a=new n(r),i=[r.__beforeBegin,r["on:begin"]]
;for(const n of i)if(n&&(n(e,a),a.ignore))return f(t)
;return r&&r.endSameAsBegin&&(r.endRe=RegExp(t.replace(/[-/\\^$*+?.()|[\]{}]/g,"\\$&"),"m")),
r.skip?O+=t:(r.excludeBegin&&(O+=t),
c(),r.returnBegin||r.excludeBegin||(O=t)),g(r),r.returnBegin?0:t.length}(a)
;if("illegal"===a.type&&!r){
const e=Error('Illegal lexeme "'+i+'" for mode "'+(y.className||"<unnamed>")+'"')
;throw e.mode=y,e}if("end"===a.type){var l=b(a);if(l!==B)return l}
if("illegal"===a.type&&""===i)return 1
;if(T>1e5&&T>3*a.index)throw Error("potential infinite loop, way more iterations than matches")
;return O+=i,i.length}var _=E(e)
;if(!_)throw console.error(u.replace("{}",e)),Error('Unknown language: "'+e+'"')
;var w=k(_),N="",y=i||w,R={},M=new d.__emitter(d);!function(){
for(var e=[],n=y;n!==_;n=n.parent)n.className&&e.unshift(n.className)
;e.forEach((e=>M.openNode(e)))}();var O="",L=0,j=0,T=0,S=!1;try{
for(y.matcher.considerAll();;){
T++,S?S=!1:y.matcher.considerAll(),y.matcher.lastIndex=j
;const e=y.matcher.exec(s);if(!e)break;const n=x(s.substring(j,e.index),e)
;j=e.index+n}return x(s.substr(j)),M.closeAllNodes(),M.finalize(),N=M.toHTML(),{
relevance:L,value:N,language:e,illegal:!1,emitter:M,top:y}}catch(n){
if(n.message&&n.message.includes("Illegal"))return{illegal:!0,illegalBy:{
msg:n.message,context:s.slice(j-100,j+100),mode:n.mode},sofar:N,relevance:0,
value:I(s),emitter:M};if(o)return{illegal:!1,relevance:0,value:I(s),emitter:M,
language:e,top:y,errorRaised:n};throw n}}function m(e,n){
n=n||d.languages||Object.keys(a);var t=function(e){const n={relevance:0,
emitter:new d.__emitter(d),value:I(e),illegal:!1,top:g}
;return n.emitter.addText(e),n}(e),r=t
;return n.filter(E).filter(w).forEach((function(n){var a=p(n,e,!1);a.language=n,
a.relevance>r.relevance&&(r=a),a.relevance>t.relevance&&(r=t,t=a)
})),r.language&&(t.second_best=r),t}function b(e){
return d.tabReplace||d.useBR?e.replace(l,(e=>"\n"===e?d.useBR?"<br>":e:d.tabReplace?e.replace(/\t/g,d.tabReplace):e)):e
}function v(e){let n=null;const t=function(e){var n=e.className+" "
;n+=e.parentNode?e.parentNode.className:"";const t=d.languageDetectRe.exec(n)
;if(t){var r=E(t[1])
;return r||(console.warn(u.replace("{}",t[1])),console.warn("Falling back to no-highlight mode for this block.",e)),
r?t[1]:"no-highlight"}return n.split(/\s+/).find((e=>h(e)||E(e)))}(e)
;if(h(t))return;N("before:highlightBlock",{block:e,language:t
}),d.useBR?(n=document.createElement("div"),
n.innerHTML=e.innerHTML.replace(/\n/g,"").replace(/<br[ /]*>/g,"\n")):n=e
;const r=n.textContent,a=t?f(t,r,!0):m(r),s=S(n);if(s.length){
const e=document.createElement("div");e.innerHTML=a.value,a.value=A(s,S(e),r)}
a.value=b(a.value),N("after:highlightBlock",{block:e,result:a
}),e.innerHTML=a.value,e.className=function(e,n,t){var r=n?i[n]:t,a=[e.trim()]
;return e.match(/\bhljs\b/)||a.push("hljs"),
e.includes(r)||a.push(r),a.join(" ").trim()
}(e.className,t,a.language),e.result={language:a.language,re:a.relevance,
relavance:a.relevance},a.second_best&&(e.second_best={
language:a.second_best.language,re:a.second_best.relevance,
relavance:a.second_best.relevance})}const x=()=>{if(!x.called){x.called=!0
;var e=document.querySelectorAll("pre code");r.forEach.call(e,v)}}
;function E(e){return e=(e||"").toLowerCase(),a[e]||a[i[e]]}
function _(e,{languageName:n}){"string"==typeof e&&(e=[e]),e.forEach((e=>{i[e]=n
}))}function w(e){var n=E(e);return n&&!n.disableAutodetect}function N(e,n){
var t=e;s.forEach((function(e){e[t]&&e[t](n)}))}Object.assign(t,{highlight:f,
highlightAuto:m,fixMarkup:function(e){
return console.warn("fixMarkup is deprecated and will be removed entirely in v11.0"),
console.warn("Please see https://github.com/highlightjs/highlight.js/issues/2534"),
b(e)},highlightBlock:v,configure:function(e){
e.useBR&&(console.warn("'useBR' option is deprecated and will be removed entirely in v11.0"),
console.warn("Please see https://github.com/highlightjs/highlight.js/issues/2559")),
d=T(d,e)},initHighlighting:x,initHighlightingOnLoad:function(){
window.addEventListener("DOMContentLoaded",x,!1)},
registerLanguage:function(e,n){var r=null;try{r=n(t)}catch(n){
if(console.error("Language definition for '{}' could not be registered.".replace("{}",e)),
!o)throw n;console.error(n),r=g}
r.name||(r.name=e),a[e]=r,r.rawDefinition=n.bind(null,t),
r.aliases&&_(r.aliases,{languageName:e})},listLanguages:function(){
return Object.keys(a)},getLanguage:E,registerAliases:_,
requireLanguage:function(e){var n=E(e);if(n)return n
;throw Error("The '{}' language is required, but not loaded.".replace("{}",e))},
autoDetection:w,inherit:T,addPlugin:function(e){s.push(e)},vuePlugin:j
}),t.debugMode=function(){o=!1},t.safeMode=function(){o=!0
},t.versionString="10.3.2";for(const n in y)"object"==typeof y[n]&&e(y[n])
;return Object.assign(t,y),t}({})}()
;"object"==typeof exports&&"undefined"!=typeof module&&(module.exports=hljs);hljs.registerLanguage("json",function(){"use strict";return function(n){var e={
literal:"true false null"
},i=[n.C_LINE_COMMENT_MODE,n.C_BLOCK_COMMENT_MODE],t=[n.QUOTE_STRING_MODE,n.C_NUMBER_MODE],a={
end:",",endsWithParent:!0,excludeEnd:!0,contains:t,keywords:e},l={begin:"{",
end:"}",contains:[{className:"attr",begin:/"/,end:/"/,
contains:[n.BACKSLASH_ESCAPE],illegal:"\\n"},n.inherit(a,{begin:/:/
})].concat(i),illegal:"\\S"},s={begin:"\\[",end:"\\]",contains:[n.inherit(a)],
illegal:"\\S"};return t.push(l,s),i.forEach((function(n){t.push(n)})),{
name:"JSON",contains:t,keywords:e,illegal:"\\S"}}}());