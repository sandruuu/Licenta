package transport

const browserPageStyles = `
:root{
  --color-white-smoke:#f2f2f0;
  --color-cool-steel:#a0a6a8;
  --color-stormy-teal:#2c6164;
  --color-graphite:#2a2a2a;
  --color-surface:#fafafa;
  --color-surface-card:#eeeeec;
  --color-surface-hover:#e4e6e5;
  --color-surface-secondary:#dedfdd;
  --color-border:#c4c8c8;
  --color-border-light:#e0e1df;
  --color-text-primary:#2a2a2a;
  --color-text-secondary:#676d6e;
  --color-text-muted:#888d8e;
  --color-accent:#2c6164;
  --color-accent-hover:#294e50;
  --color-accent-muted:rgba(44,97,100,.14);
  --color-danger:#b42318;
  --color-danger-muted:#f7dfdd;
  --color-warning:#9a6500;
  --color-warning-muted:#fbf2d7;
  color-scheme:light;
}
*{box-sizing:border-box;margin:0;padding:0}
html,body{
  min-width:320px;
  min-height:100vh;
  color-scheme:light;
}
body{
  font-family:Inter,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
  background:var(--color-surface);
  color:var(--color-text-primary);
  line-height:1.6;
  -webkit-font-smoothing:antialiased;
  display:grid;
  min-height:100vh;
  place-items:center;
  padding:24px 16px;
}
a{color:var(--color-accent);text-decoration:none}
a:hover{color:var(--color-accent-hover)}
.panel{
  width:min(400px,100%);
  background:var(--color-surface-card);
  border:1px solid var(--color-border);
  border-radius:6px;
  padding:32px;
  box-shadow:0 18px 36px rgba(42,42,42,.14);
  animation:cardFadeIn .35s ease-out both;
}
.panel-wide{width:min(560px,100%)}
.brand{
  display:flex;
  flex-direction:column;
  align-items:center;
  justify-content:center;
  gap:8px;
  text-align:center;
  margin-bottom:28px;
}
.brand-icon{
  display:grid;
  width:80px;
  height:80px;
  place-items:center;
}
.brand-icon svg{
  width:80px;
  height:80px;
  display:block;
}
.brand-title{
  color:var(--color-text-primary);
  font-size:24px;
  font-weight:700;
  line-height:1;
}
.brand-title span{color:var(--color-accent)}
h1{
  margin:0 0 10px;
  color:var(--color-text-primary);
  font-size:22px;
  font-weight:700;
  line-height:1.2;
  text-align:center;
}
h2{
  margin:0 0 6px;
  color:var(--color-text-primary);
  font-size:16px;
  font-weight:700;
  line-height:1.35;
}
p{
  margin:0 0 14px;
  color:var(--color-text-secondary);
  line-height:1.5;
}
form{
  display:grid;
  gap:18px;
  width:100%;
  max-width:300px;
  margin:26px auto 0;
}
.form-actions{
  display:grid;
  gap:10px;
  justify-items:center;
}
label{
  display:block;
  margin-bottom:8px;
  color:var(--color-text-secondary);
  font-size:11px;
  font-weight:700;
  letter-spacing:0;
  text-transform:uppercase;
}
input:not([type="hidden"]){
  width:100%;
  height:40px;
  border:1px solid var(--color-border);
  border-radius:10px;
  background:var(--color-surface);
  color:var(--color-text-primary);
  padding:0 16px;
  font-family:inherit;
  font-size:13px;
  letter-spacing:0;
  outline:none;
  transition:border-color .15s ease,box-shadow .15s ease,background-color .15s ease;
}
input::placeholder{color:var(--color-text-muted)}
input:focus{
  border-color:var(--color-accent);
  box-shadow:0 0 0 4px var(--color-accent-muted);
}
button,.button-link{
  display:inline-flex;
  align-items:center;
  justify-content:center;
  width:100%;
  max-width:220px;
  min-height:40px;
  margin:6px auto 0;
  border:1px solid var(--color-accent);
  border-radius:999px;
  background:var(--color-accent);
  color:var(--color-white-smoke);
  cursor:pointer;
  padding:0 20px;
  font-family:inherit;
  font-size:13px;
  font-weight:600;
  line-height:1;
  text-decoration:none;
  box-shadow:0 8px 16px rgba(42,42,42,.18);
  transition:background-color .15s ease,color .15s ease,opacity .15s ease,box-shadow .15s ease;
}
button:hover,.button-link:hover{
  background:var(--color-accent-hover);
  color:var(--color-white-smoke);
}
button.secondary{
  margin-top:0;
  border-color:var(--color-border);
  background:var(--color-surface-card);
  color:var(--color-text-secondary);
  box-shadow:0 8px 16px rgba(42,42,42,.12);
}
button.secondary:hover{
  background:var(--color-surface-hover);
  color:var(--color-text-primary);
}
button:disabled{cursor:wait;opacity:.65}
.alert{
  margin:14px 0;
  border:0;
  background:transparent;
  color:var(--color-danger);
  padding:0;
  font-size:13px;
  font-weight:600;
  text-align:left;
}
.page-alert{
  display:flex;
  gap:10px;
  align-items:center;
  max-width:320px;
  min-height:40px;
  margin:0 auto 16px;
  border:0;
  background:transparent;
  color:var(--color-danger);
  padding:0;
  font-size:14px;
  font-weight:400;
  line-height:18px;
  text-align:left;
}
.page-alert svg{
  width:18px;
  height:18px;
  flex-shrink:0;
  color:var(--color-danger);
}
.notice{
  margin-top:14px;
  border:1px solid var(--color-warning);
  border-radius:6px;
  background:var(--color-warning-muted);
  color:var(--color-warning);
  padding:12px;
  font-size:13px;
  line-height:1.5;
}
.status{
  min-height:18px;
  margin-top:12px;
  color:var(--color-text-secondary);
  font-size:13px;
}
.page-copy{
  max-width:300px;
  margin:0 auto;
  color:var(--color-text-secondary);
  font-size:14px;
  line-height:1.45;
  text-align:left;
}
.completion-mark{
  display:block;
  width:72px;
  height:72px;
  margin:24px auto 0;
  color:var(--color-accent);
  overflow:visible;
}
.completion-ring,.completion-check{
  fill:none;
  stroke:currentColor;
  stroke-linecap:round;
  stroke-linejoin:round;
}
.completion-ring{
  stroke-width:4.4;
  stroke-dasharray:1;
  stroke-dashoffset:1;
  animation:completionCircle .62s cubic-bezier(.2,.85,.25,1) forwards;
}
.completion-check{
  stroke-width:5.8;
  stroke-dasharray:1;
  stroke-dashoffset:1;
  animation:completionCheck .34s ease-out .55s forwards;
}
.cancel-mark{
  display:block;
  width:72px;
  height:72px;
  margin:24px auto 0;
  color:var(--color-danger);
  overflow:visible;
}
.cancel-ring,.cancel-cross-first,.cancel-cross-second{
  fill:none;
  stroke:currentColor;
  stroke-linecap:round;
  stroke-linejoin:round;
}
.cancel-ring{
  stroke-width:4.4;
  stroke-dasharray:1;
  stroke-dashoffset:1;
  transform:rotate(-90deg);
  transform-origin:36px 36px;
  animation:completionCircle .62s cubic-bezier(.2,.85,.25,1) forwards;
}
.cancel-cross-first,.cancel-cross-second{
  stroke-width:5.8;
  stroke-dasharray:1;
  stroke-dashoffset:1;
}
.cancel-cross-first{
  animation:completionCheck .3s ease-out .55s forwards;
}
.cancel-cross-second{
  animation:completionCheck .3s ease-out .88s forwards;
}
@keyframes cardFadeIn{
  from{opacity:0;transform:translateY(8px)}
  to{opacity:1;transform:translateY(0)}
}
@keyframes completionCircle{
  to{stroke-dashoffset:0}
}
@keyframes completionCheck{
  to{stroke-dashoffset:0}
}
`

const browserBrandMarkup = `<div class="brand"><div class="brand-icon" aria-hidden="true"><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512"><defs><mask id="browser-logo-connector-gap" maskUnits="userSpaceOnUse" x="0" y="0" width="512" height="512"><rect width="512" height="512" fill="white"/><path d="M256 120c26 21 56 31 88 31v75c0 56-36 90-88 112-52-22-88-56-88-112v-75c32 0 62-10 88-31z" fill="black" stroke="black" stroke-width="18" stroke-linejoin="round"/><g fill="black" stroke="black" stroke-width="8" stroke-linejoin="round"><rect x="64" y="233" width="30" height="30" rx="4"/><rect x="418" y="233" width="30" height="30" rx="4"/><rect x="92" y="78" width="28" height="28" rx="4"/><circle cx="106" cy="181" r="15"/><rect x="392" y="78" width="28" height="28" rx="4"/><circle cx="406" cy="181" r="15"/><rect x="242" y="37" width="28" height="28" rx="4"/></g></mask></defs><g fill="none" stroke="#2a2a2a" stroke-width="8" stroke-linecap="round" stroke-linejoin="round"><path d="M64 286v74c0 12 10 22 22 22h340c12 0 22-10 22-22v-74"/><path d="M210 382v34"/><path d="M302 382v34"/><path d="M196 416h124"/></g><g mask="url(#browser-logo-connector-gap)" fill="none" stroke="#2a2a2a" stroke-width="8" stroke-linecap="round" stroke-linejoin="round"><path d="M79 248h354"/><path d="M106 92v89"/><path d="M106 181l119 48"/><path d="M406 92v89"/><path d="M406 181l-119 48"/><path d="M256 51v111"/></g><g fill="none" stroke="#2a2a2a" stroke-width="8" stroke-linecap="round" stroke-linejoin="round"><rect x="64" y="233" width="30" height="30" rx="4"/><rect x="418" y="233" width="30" height="30" rx="4"/><rect x="92" y="78" width="28" height="28" rx="4"/><circle cx="106" cy="181" r="15"/><rect x="392" y="78" width="28" height="28" rx="4"/><circle cx="406" cy="181" r="15"/><rect x="242" y="37" width="28" height="28" rx="4"/></g><path d="M256 120c26 21 56 31 88 31v75c0 56-36 90-88 112-52-22-88-56-88-112v-75c32 0 62-10 88-31z" fill="none" stroke="#2c6164" stroke-width="8" stroke-linecap="round" stroke-linejoin="round"/><g fill="#2c6164"><circle cx="256" cy="205" r="12"/><path d="M250 214h12l9 55h-30z"/></g></svg></div><div class="brand-title"><span>TRUST</span>Cloud</div></div>`
