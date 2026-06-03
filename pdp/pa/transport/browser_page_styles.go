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
  box-shadow:0 8px 24px rgba(42,42,42,.14);
  animation:cardFadeIn .35s ease-out both;
}
.panel-wide{width:min(560px,100%)}
.brand{
  text-align:center;
  margin-bottom:24px;
}
.brand-title{
  color:var(--color-text-primary);
  font-size:20px;
  font-weight:700;
  line-height:1;
}
.brand-title span{color:var(--color-accent)}
h1{
  margin:0 0 8px;
  color:var(--color-text-primary);
  font-size:24px;
  font-weight:700;
  line-height:1.25;
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
  gap:12px;
  margin-top:20px;
}
label{
  display:block;
  margin-bottom:6px;
  color:var(--color-text-secondary);
  font-size:11px;
  font-weight:700;
  letter-spacing:.2px;
  text-transform:uppercase;
}
input:not([type="hidden"]){
  width:100%;
  height:42px;
  border:1px solid var(--color-border);
  border-radius:6px;
  background:var(--color-surface);
  color:var(--color-text-primary);
  padding:0 12px;
  font-family:inherit;
  font-size:13px;
  letter-spacing:0;
  outline:none;
  transition:border-color .15s ease,box-shadow .15s ease,background-color .15s ease;
}
input::placeholder{color:var(--color-text-muted)}
input:focus{
  border-color:var(--color-accent);
  box-shadow:0 0 0 3px var(--color-accent-muted);
}
button,.button-link{
  display:inline-flex;
  align-items:center;
  justify-content:center;
  min-height:40px;
  border:0;
  border-radius:6px;
  background:var(--color-accent);
  color:var(--color-white-smoke);
  cursor:pointer;
  padding:0 16px;
  font-family:inherit;
  font-size:12px;
  font-weight:700;
  line-height:1;
  text-decoration:none;
  transition:background-color .15s ease,color .15s ease,opacity .15s ease;
}
button:hover,.button-link:hover{
  background:var(--color-accent-hover);
  color:var(--color-white-smoke);
}
button:disabled{cursor:wait;opacity:.65}
.alert{
  margin:14px 0;
  border:1px solid var(--color-danger);
  border-radius:6px;
  background:var(--color-danger-muted);
  color:var(--color-danger);
  padding:10px 12px;
  font-size:13px;
  font-weight:700;
  text-align:center;
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
@keyframes cardFadeIn{
  from{opacity:0;transform:translateY(8px)}
  to{opacity:1;transform:translateY(0)}
}
`

const browserBrandMarkup = `<div class="brand"><div class="brand-title"><span>TRUST</span>Cloud</div></div>`
