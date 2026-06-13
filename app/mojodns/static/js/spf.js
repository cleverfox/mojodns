/* SPF constructor: editable term rows + live preview, kept in sync with the
   raw #spf-content field. Server (spf.py) is the authoritative validator on
   save; this gives instant feedback. */
(function () {
  "use strict";
  var QUALS = [["+", "+ pass"], ["-", "- fail"], ["~", "~ softfail"], ["?", "? neutral"]];
  // kind -> {value: 'none'|'domain'|'ip'|'amx', hint}
  var KINDS = {
    "all":      {value: "none"},
    "ip4":      {value: "ip",     hint: "192.0.2.0/24"},
    "ip6":      {value: "ip",     hint: "2001:db8::/32"},
    "include":  {value: "domain", hint: "_spf.example.com"},
    "a":        {value: "amx",    hint: "(optional) domain or /cidr"},
    "mx":       {value: "amx",    hint: "(optional) domain or /cidr"},
    "exists":   {value: "domain", hint: "%{i}._spf.example.com"},
    "ptr":      {value: "amx",    hint: "(optional, deprecated)"},
    "redirect": {value: "domain", hint: "_spf.example.com", modifier: true},
    "exp":      {value: "domain", hint: "explain.example.com", modifier: true}
  };

  var builder = document.getElementById("spf-builder");
  if (!builder) return;
  var controls = document.getElementById("spf-builder-controls");
  var contentEl = document.getElementById("spf-content");
  var previewEl = document.getElementById("spf-preview");
  var msgsEl = document.getElementById("spf-live-msgs");
  var terms = [];

  try { terms = JSON.parse(document.getElementById("spf-init").textContent) || []; }
  catch (e) { terms = []; }

  function el(tag, attrs, kids) {
    var n = document.createElement(tag);
    attrs = attrs || {};
    for (var k in attrs) { if (k === "class") n.className = attrs[k]; else n.setAttribute(k, attrs[k]); }
    (kids || []).forEach(function (c) { n.appendChild(typeof c === "string" ? document.createTextNode(c) : c); });
    return n;
  }
  function opt(v, label, sel) {
    var o = el("option", {value: v}, [label]); if (sel) o.selected = true; return o;
  }

  function render() {
    builder.innerHTML = "";
    terms.forEach(function (t, i) {
      var row = el("div", {class: "spf-row"});
      var meta = KINDS[t.kind] || {value: "domain"};
      var isMod = meta.modifier;

      // qualifier (mechanisms only)
      var qsel = el("select", {class: "spf-q"});
      QUALS.forEach(function (q) { qsel.appendChild(opt(q[0], q[1], (t.qualifier || "+") === q[0])); });
      qsel.disabled = isMod;
      qsel.style.visibility = isMod ? "hidden" : "visible";
      qsel.onchange = function () { t.qualifier = qsel.value; sync(); };
      row.appendChild(qsel);

      // kind
      var ksel = el("select", {class: "spf-k"});
      Object.keys(KINDS).forEach(function (k) { ksel.appendChild(opt(k, k, t.kind === k)); });
      if (!KINDS[t.kind]) ksel.appendChild(opt(t.kind, t.kind + " (?)", true));
      ksel.onchange = function () {
        t.kind = ksel.value;
        if ((KINDS[t.kind] || {}).value === "none") t.value = "";
        if ((KINDS[t.kind] || {}).modifier) t.qualifier = "";
        else if (!t.qualifier) t.qualifier = "+";
        render(); sync();
      };
      row.appendChild(ksel);

      // value
      var val = el("input", {class: "spf-v mono", value: t.value || "", placeholder: meta.hint || ""});
      val.disabled = (meta.value === "none");
      val.oninput = function () { t.value = val.value.trim(); sync(); };
      row.appendChild(val);

      // controls
      var up = el("button", {type: "button", class: "btn btn-ghost", title: "move up"}, ["↑"]);
      up.onclick = function () { if (i > 0) { terms.splice(i - 1, 0, terms.splice(i, 1)[0]); render(); sync(); } };
      var dn = el("button", {type: "button", class: "btn btn-ghost", title: "move down"}, ["↓"]);
      dn.onclick = function () { if (i < terms.length - 1) { terms.splice(i + 1, 0, terms.splice(i, 1)[0]); render(); sync(); } };
      var rm = el("button", {type: "button", class: "btn btn-ghost btn-danger", title: "remove"}, ["×"]);
      rm.onclick = function () { terms.splice(i, 1); render(); sync(); };
      row.appendChild(up); row.appendChild(dn); row.appendChild(rm);
      builder.appendChild(row);
    });
  }

  function renderTerm(t) {
    if (!t.kind) return "";
    var meta = KINDS[t.kind] || {};
    if (meta.modifier) return t.kind + "=" + (t.value || "");
    // '+' is SPF's default qualifier, so omit it for a cleaner record
    var s = (t.qualifier && t.qualifier !== "+" ? t.qualifier : "") + t.kind;
    if (!t.value || meta.value === "none") return s;
    if (t.kind === "a" || t.kind === "mx" || t.kind === "ptr")
      return s + (t.value.charAt(0) === "/" ? t.value : ":" + t.value);
    return s + ":" + t.value;
  }

  function validate() {
    var msgs = [];
    var lookups = 0, sawAll = false;
    terms.forEach(function (t) {
      var meta = KINDS[t.kind];
      if (!meta) { msgs.push("unknown mechanism '" + t.kind + "'"); return; }
      if (["include", "a", "mx", "ptr", "exists", "redirect"].indexOf(t.kind) >= 0) lookups++;
      if (meta.value === "none" && t.value) msgs.push("'" + t.kind + "' takes no value");
      if ((t.kind === "include" || t.kind === "exists" || t.kind === "redirect") && !t.value)
        msgs.push("'" + t.kind + "' needs a domain");
      if ((t.kind === "ip4" || t.kind === "ip6") && !t.value) msgs.push("'" + t.kind + "' needs an address");
      if (t.kind === "all") { if (sawAll) {} sawAll = true; }
      else if (sawAll && meta && !meta.modifier) msgs.push("'" + t.kind + "' is after 'all' — never evaluated");
    });
    if (lookups > 10) msgs.push(lookups + " DNS-lookup terms exceed the limit of 10");
    return msgs;
  }

  function sync() {
    var rec = "v=spf1" + terms.map(function (t) { var r = renderTerm(t); return r ? " " + r : ""; }).join("");
    contentEl.value = rec;
    previewEl.textContent = rec;
    var msgs = validate();
    msgsEl.innerHTML = "";
    msgs.forEach(function (m) {
      var d = el("div", {class: "flash flash-warn"}, [m]); msgsEl.appendChild(d);
    });
  }

  // if the user edits the raw field directly, rebuild rows from it
  contentEl.addEventListener("change", function () {
    var toks = contentEl.value.trim().split(/\s+/);
    if (toks[0] && toks[0].toLowerCase() === "v=spf1") toks = toks.slice(1);
    terms = toks.filter(Boolean).map(parseToken);
    render(); sync();
  });

  function parseToken(tok) {
    var lower = tok.toLowerCase();
    var modName = tok.split("=")[0].toLowerCase();
    if (tok.indexOf("=") >= 0 && (modName === "redirect" || modName === "exp"))
      return {qualifier: "", kind: modName, value: tok.slice(tok.indexOf("=") + 1)};
    var qual = "+", body = tok;
    if ("+-~?".indexOf(tok.charAt(0)) >= 0) { qual = tok.charAt(0); body = tok.slice(1); }
    var name = body, value = "";
    if (body.indexOf(":") >= 0) { name = body.slice(0, body.indexOf(":")); value = body.slice(body.indexOf(":") + 1); }
    else if (body.indexOf("/") >= 0 && ["a", "mx", "ptr"].indexOf(body.split("/")[0].toLowerCase()) >= 0) {
      name = body.slice(0, body.indexOf("/")); value = body.slice(body.indexOf("/"));
    }
    return {qualifier: qual, kind: name.toLowerCase(), value: value};
  }

  document.getElementById("spf-add").onclick = function () {
    terms.push({qualifier: "+", kind: "include", value: ""}); render(); sync();
  };

  controls.style.display = "";
  render();
  sync();
})();
