(function () {
  "use strict";

  /* ---------------- helpers ---------------- */
  var $ = function (id) { return document.getElementById(id); };
  var token = null;
  try { token = sessionStorage.getItem("bp_token"); } catch (e) {}
  var me = null;
  var formTypes = [];
  var activeForm = null;
  var pending = null; // { challengeId, accNo }

  function store(key, val) { try { localStorage.setItem(key, val); } catch (e) {} }
  function load(key) { try { return localStorage.getItem(key); } catch (e) { return null; } }

  // Always render server/user text with textContent, never innerHTML (prevents XSS).
  function el(tag, cls, text) {
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text !== undefined) n.textContent = text;
    return n;
  }
  function showMsg(node, text, kind) { node.textContent = text; node.className = "msg " + (kind || "error"); node.hidden = false; }
  function hideMsg(node) { node.hidden = true; }
  function when(epoch) {
    return new Date(epoch * 1000).toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
  }

  async function api(path, opts) {
    opts = opts || {};
    var headers = { "Content-Type": "application/json" };
    if (token) headers["Authorization"] = "Bearer " + token;
    var res;
    try {
      res = await fetch("/api" + path, {
        method: opts.method || "GET", headers: headers,
        body: opts.body ? JSON.stringify(opts.body) : undefined
      });
    } catch (e) {
      throw { code: "NETWORK", message: "Cannot reach the server. Check your internet connection." };
    }
    var data = {};
    try { data = await res.json(); } catch (e) {}
    if (!res.ok) {
      var err = { status: res.status, code: data.code, message: data.message || "Something went wrong." };
      if (err.code === "UNAUTHENTICATED" || err.code === "SESSION_EXPIRED") { goToLogin(err.message); }
      throw err;
    }
    return data;
  }

  function busy(btn, fn) {
    return async function () {
      btn.disabled = true;
      try { await fn(); } finally { btn.disabled = false; }
    };
  }

  /* ---------------- auth screens ---------------- */
  var viewLogin = $("view-login"), viewOtp = $("view-otp"), viewCreate = $("view-create");
  var tabLogin = $("tab-login"), tabCreate = $("tab-create"), tabs = $("auth-tabs");

  function selectTab(which) {
    var login = which === "login";
    tabs.hidden = false;
    tabLogin.setAttribute("aria-selected", String(login));
    tabCreate.setAttribute("aria-selected", String(!login));
    viewLogin.hidden = !login; viewCreate.hidden = login; viewOtp.hidden = true;
  }
  tabLogin.addEventListener("click", function () { selectTab("login"); });
  tabCreate.addEventListener("click", function () { selectTab("create"); });

  function goToLogin(message) {
    token = null; me = null;
    try { sessionStorage.removeItem("bp_token"); } catch (e) {}
    $("screen-dashboard").hidden = true; $("screen-auth").hidden = false;
    selectTab("login");
    if (message) showMsg($("login-msg"), message, "info");
  }

  $("btn-create").addEventListener("click", busy($("btn-create"), async function () {
    var msg = $("create-msg");
    try {
      var r = await api("/register", { method: "POST", body: {
        name: $("create-name").value, phone: $("create-phone").value, pin: $("create-pin").value } });
      store("bp_device_" + r.acc_no, r.device_token);   // this browser = trusted device
      showMsg(msg, "Account created. Your account number is " + r.acc_no + ". This device is now your trusted device.", "ok");
      $("create-name").value = ""; $("create-phone").value = ""; $("create-pin").value = "";
      setTimeout(function () { $("login-acc").value = String(r.acc_no); selectTab("login"); hideMsg(msg); }, 1600);
    } catch (e) { showMsg(msg, e.message, "error"); }
  }));

  $("btn-login").addEventListener("click", busy($("btn-login"), async function () {
    var msg = $("login-msg"), lock = $("lock-banner");
    hideMsg(msg); hideMsg(lock);
    var acc = $("login-acc").value.trim();
    var simulate = $("login-new-device").checked;
    var body = { acc_no: acc, pin: $("login-pin").value };
    var dev = load("bp_device_" + acc);
    if (dev && !simulate) body.device_token = dev;
    try {
      var r = await api("/login", { method: "POST", body: body });
      pending = { challengeId: r.challenge_id, accNo: acc };
      $("otp-info").textContent = r.demo_otp
        ? "Demo mode - no real SMS is sent. Your code for " + r.phone_masked + " is: " + r.demo_otp
        : "A 6-digit code was sent to " + r.phone_masked + ".";
      $("otp-input").value = ""; hideMsg($("otp-msg"));
      tabs.hidden = true; viewLogin.hidden = true; viewCreate.hidden = true; viewOtp.hidden = false;
      $("login-pin").value = "";
    } catch (e) {
      if (e.code === "ACCOUNT_LOCKED") showMsg(lock, e.message, "error"); else showMsg(msg, e.message, "error");
    }
  }));

  $("btn-otp-back").addEventListener("click", function () { pending = null; selectTab("login"); });

  $("btn-verify-otp").addEventListener("click", busy($("btn-verify-otp"), async function () {
    var msg = $("otp-msg");
    try {
      var r = await api("/verify-otp", { method: "POST", body: { challenge_id: pending.challengeId, otp: $("otp-input").value.trim() } });
      token = r.token;
      try { sessionStorage.setItem("bp_token", token); } catch (e) {}
      if (r.device_token) store("bp_device_" + pending.accNo, r.device_token);
      pending = null;
      await openDashboard();
    } catch (e) {
      showMsg(msg, e.message, "error");
      if (e.code === "OTP_LOCKED" || e.code === "OTP_EXPIRED") { setTimeout(function () { selectTab("login"); }, 1500); }
    }
  }));

  /* ---------------- dashboard ---------------- */
  var panels = ["deposit", "withdraw", "transfer", "history", "forms"];
  function showPanel(name) {
    panels.forEach(function (p) {
      $("panel-" + p).hidden = (p !== name);
      document.querySelector('.action-btn[data-action="' + p + '"]').setAttribute("aria-pressed", String(p === name));
    });
  }
  document.querySelectorAll(".action-btn").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var a = btn.getAttribute("data-action");
      showPanel($("panel-" + a).hidden ? a : null);
    });
  });

  async function refreshMe() {
    me = await api("/me");
    $("dash-hello").textContent = "Welcome back, " + me.name;
    $("dash-balance").textContent = "\u20B9" + me.balance;
    $("dash-acc").textContent = "#" + me.acc_no;
    $("device-banner").hidden = me.trusted;
    $("device-banner-text").textContent =
      "This is not your trusted device. You can view your account, but deposits, withdrawals, transfers and most forms are blocked. " +
      "To switch devices, submit a \"Change trusted device\" request under Forms - the bank verifies you before approving it.";
  }

  async function openDashboard() {
    await refreshMe();
    $("screen-auth").hidden = true; $("screen-dashboard").hidden = false;
    var t = await api("/forms/types");
    formTypes = t.items;
    if (!activeForm || !formTypes.some(function (f) { return f.id === activeForm; })) activeForm = formTypes[0].id;
    renderFormChips(); renderFormFields();
    await Promise.all([loadHistory(), loadRequests()]);
    showPanel(null);
  }

  async function loadHistory() {
    var r = await api("/history");
    var list = $("history-list");
    list.textContent = "";
    $("history-empty").hidden = r.items.length > 0;
    r.items.forEach(function (tx) {
      var li = el("li");
      var left = el("span");
      left.appendChild(el("span", "", tx.type));
      left.appendChild(el("span", "tx-time", when(tx.created_at)));
      li.appendChild(left);
      li.appendChild(el("span", "tx-amt " + (tx.amount.charAt(0) === "-" ? "neg" : "pos"), tx.amount));
      list.appendChild(li);
    });
  }

  function money(btn, path, bodyFn, inputs, msgId, okText) {
    $(btn).addEventListener("click", busy($(btn), async function () {
      var msg = $(msgId);
      try {
        var r = await api(path, { method: "POST", body: bodyFn() });
        inputs.forEach(function (i) { $(i).value = ""; });
        showMsg(msg, okText + " New balance: \u20B9" + r.balance, "ok");
        await refreshMe(); await loadHistory();
      } catch (e) { showMsg(msg, e.message, "error"); }
    }));
  }
  money("btn-deposit", "/deposit", function () { return { amount: $("deposit-amt").value }; }, ["deposit-amt"], "deposit-msg", "Deposit successful.");
  money("btn-withdraw", "/withdraw", function () { return { amount: $("withdraw-amt").value }; }, ["withdraw-amt"], "withdraw-msg", "Withdrawal successful.");
  money("btn-transfer", "/transfer", function () { return { to_acc: $("transfer-acc").value, amount: $("transfer-amt").value }; },
    ["transfer-acc", "transfer-amt"], "transfer-msg", "Transfer successful.");

  /* ---------------- paperless forms ---------------- */
  function renderFormChips() {
    var wrap = $("form-type-chips");
    wrap.textContent = "";
    formTypes.forEach(function (ft) {
      var b = el("button", "chip", ft.label);
      b.type = "button";
      b.setAttribute("aria-pressed", String(ft.id === activeForm));
      b.addEventListener("click", function () { activeForm = ft.id; hideMsg($("form-msg")); renderFormChips(); renderFormFields(); });
      wrap.appendChild(b);
    });
  }

  function renderFormFields() {
    var ft = formTypes.find(function (f) { return f.id === activeForm; });
    var box = $("form-fields");
    box.textContent = "";
    var note = $("form-note");
    if (ft.needs_trusted && me && !me.trusted) {
      showMsg(note, "This form can only be submitted from your trusted device.", "info");
    } else if (!ft.needs_trusted) {
      showMsg(note, "The bank will call your alternate number to verify you before changing the trusted device.", "info");
    } else { note.hidden = true; }
    ft.fields.forEach(function (f) {
      var lab = el("label", "", f.label);
      lab.setAttribute("for", "ff-" + f.id);
      box.appendChild(lab);
      var input;
      if (f.kind === "select") {
        input = el("select");
        f.options.forEach(function (o) { var opt = el("option", "", o); opt.value = o; input.appendChild(opt); });
      } else if (f.kind === "textarea") {
        input = el("textarea");
      } else {
        input = el("input", f.mono ? "mono" : "");
      }
      if (f.placeholder) input.placeholder = f.placeholder;
      if (f.maxlength) input.maxLength = f.maxlength;
      input.id = "ff-" + f.id;
      box.appendChild(input);
    });
  }

  $("btn-submit-form").addEventListener("click", busy($("btn-submit-form"), async function () {
    var msg = $("form-msg");
    var ft = formTypes.find(function (f) { return f.id === activeForm; });
    var fields = {};
    ft.fields.forEach(function (f) { fields[f.id] = $("ff-" + f.id).value; });
    try {
      await api("/forms", { method: "POST", body: { type: ft.id, fields: fields } });
      showMsg(msg, ft.label + " request submitted - no branch visit needed.", "ok");
      renderFormFields();
      await loadRequests();
    } catch (e) { showMsg(msg, e.message, "error"); }
  }));

  async function loadRequests() {
    var r = await api("/forms");
    var list = $("req-list");
    list.textContent = "";
    $("req-empty").hidden = r.items.length > 0;
    r.items.forEach(function (req) {
      var li = el("li");
      var top = el("div", "req-top");
      top.appendChild(el("span", "", req.type));
      top.appendChild(el("span", "status-pill", req.status));
      li.appendChild(top);
      req.details.forEach(function (d) { li.appendChild(el("span", "req-sub", d.label + ": " + d.value)); });
      li.appendChild(el("span", "req-sub", when(req.created_at)));
      list.appendChild(li);
    });
  }

  $("btn-go-device-form").addEventListener("click", function () {
    activeForm = "device"; renderFormChips(); renderFormFields(); showPanel("forms");
  });

  $("btn-logout").addEventListener("click", async function () {
    try { await api("/logout", { method: "POST", body: {} }); } catch (e) {}
    $("login-acc").value = ""; $("login-pin").value = ""; $("login-new-device").checked = false;
    hideMsg($("login-msg")); hideMsg($("lock-banner"));
    goToLogin();
  });

  /* ---------------- start ---------------- */
  (async function init() {
    if (token) {
      try { await openDashboard(); return; } catch (e) { /* fall through to login */ }
    }
    selectTab("login");
  })();
})();
