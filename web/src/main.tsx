// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf

import packageInfo from "../package.json";
import React, { useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import {
  ShieldCheck,
  LayoutDashboard,
  Layers,
  Inbox,
  Activity,
  History,
  LogOut,
  Menu,
  X,
  ArrowRight,
  LockKeyhole,
  Server,
  ShieldHalf,
  Rocket,
  ListChecks,
  KeyRound,
  TerminalSquare,
} from "lucide-react";
import { ApiError, SESSION_ENDED, Session, api, useCSRF, setCustomerPolicy } from "./api";
import { Loading, ErrorBox } from "./components";
import {
  Overview,
  Policies,
  PolicyDetail,
  Requests,
  Runs,
  RunDetail,
  AuditExplorer,
} from "./pages";
import "./style.css";
import { LocalLogin } from "./local-login";
import { Users } from "./users";
import { PolicyWorkspace } from "./policy-workspace";
import { TargetDetail, Targets } from "./targets";
import { ProfileDetail, Profiles } from "./profiles";
import { LaunchPage } from "./launch-form";
import { LaunchDetail, Launches } from "./launches";
import { Secrets } from "./secrets";
import { Tokens } from "./tokens";
import { ProvisioningOverview } from "./prov-overview";
import { permissions } from "./prov-api";
import "./provisioning.css";
const nav = [
  { id: "overview", label: "Overview", icon: LayoutDashboard },
  { id: "targets", label: "Targets", icon: Server },
  { id: "profiles", label: "Access profiles", icon: ShieldHalf },
  { id: "launch", label: "Launch", icon: Rocket },
  { id: "launches", label: "Launches", icon: ListChecks },
  { id: "secrets", label: "Secrets", icon: KeyRound },
  { id: "tokens", label: "API tokens", icon: TerminalSquare },
  { id: "policies", label: "Policies", icon: Layers },
  { id: "policy-builder", label: "Policy builder", icon: ShieldCheck },
  { id: "requests", label: "Requests", icon: Inbox },
  { id: "runs", label: "Runs", icon: Activity },
  { id: "audit", label: "Audit", icon: History },
  { id: "users", label: "Local users", icon: LockKeyhole },
];
function Login() {
  const code = new URLSearchParams(location.search).get("signin_error");
  const [options, setOptions] = useState<{local: boolean; oidc: boolean; community?: boolean}>();
  useEffect(() => { fetch('/auth/options').then(r => r.ok ? r.json() : Promise.reject()).then(setOptions).catch(() => setOptions({local:false, oidc:false})); }, []);
  return (
    <main className="login-page">
      <section className="login-story">
        <div className="brand">
          <ShieldCheck />
          <span>AgentGate</span>
        </div>
        <span className="pill">Policy control</span>
        <h1>
          Clear authority.
          <br />
          Traceable decisions.
        </h1>
        <p>
          Connect the policy a worker requests to the version a human approves
          and the evidence a run retains.
        </p>
        <div className="login-path">
          <span>Identity</span>
          <ArrowRight />
          <span>Authority</span>
          <ArrowRight />
          <span>Evidence</span>
        </div>
        <small>Private operator workspace</small>
      </section>
      <section className="login-panel">
        <LockKeyhole size={27} />
        <h2>Sign in to policy control</h2>
        <p>
          Your account roles determine which records and decisions you can access.
        </p>
        {code && (
          <div className="error-box" role="alert">
            {code === "untrusted_groups"
              ? "Your Authentik groups do not grant access. Contact the application administrator."
              : "This sign-in did not complete. Start a new login."}
          </div>
        )}
        {options?.local && <LocalLogin />}
        {options?.oidc && <a className="button" href="/auth/login">
          {options.community ? 'Continue with OIDC' : 'Continue with Authentik'} <ArrowRight size={17} />
        </a>}
        {options && !options.local && !options.oidc && <div className="error-box" role="alert">Sign-in is unavailable. Contact the administrator.</div>}
        <small>
          Secure browser sessions. Policy and run history stay with the control
          plane.
        </small>
      </section>
    </main>
  );
}
function App() {
  const [session, setSession] = useState<Session | null>();
  const [error, setError] = useState<unknown>();
  const [path, setPath] = useState(
    location.hash.startsWith("#/")
      ? location.hash.slice(2) || "overview"
      : "overview",
  );
  const [epoch, setEpoch] = useState(0);
  const [mobile, setMobile] = useState(false);
  const refresh = () => setEpoch((x) => x + 1);
  const navigate = (p: string) => {
    location.hash = "/" + p;
    setMobile(false);
  };
  useEffect(() => {
    api<Session>("session")
      .then((s) => {
        useCSRF(s.csrf_token);
        setCustomerPolicy(Boolean(s.customer_policy));
        setSession(s);
      })
      .catch((e) => {
        if (e instanceof ApiError && e.status === 401) setSession(null);
        else setError(e);
      });
  }, []);
  useEffect(() => {
    const listener = () => {
      if (location.hash.startsWith("#/"))
        setPath(location.hash.slice(2) || "overview");
      document.getElementById("main-content")?.focus({ preventScroll: true });
    };
    addEventListener("hashchange", listener);
    return () => removeEventListener("hashchange", listener);
  }, []);
  useEffect(() => {
    const ended = () => setSession(null);
    addEventListener(SESSION_ENDED, ended);
    return () => removeEventListener(SESSION_ENDED, ended);
  }, []);
  const [clock, setClock] = useState(Date.now());
  useEffect(() => {
    const t = setInterval(() => setClock(Date.now()), 30000);
    return () => clearInterval(t);
  }, []);
  useEffect(() => {
    if (session && session.expires && session.expires * 1000 <= clock) setSession(null);
  }, [clock, session?.expires]);
  useEffect(() => {
    if (!session) return;
    let live = true;
    const stream = new EventSource("/api/v1/events");
    let timer: ReturnType<typeof setTimeout>;
    stream.addEventListener("changed", () => {
      clearTimeout(timer);
      timer = setTimeout(() => {
        api<Session>('session').then(current => {
          if (!live) return;
          useCSRF(current.csrf_token);
          setCustomerPolicy(Boolean(current.customer_policy));
          setSession(current);
          refresh();
        }).catch(error => {
          if (!live) return;
          if (error.status === 401) setSession(null);
          else setError(error);
        });
      }, 200);
    });
    stream.onerror = () => {
      api<Session>("session").catch((e) => {
        if (e.status === 401) {
          stream.close();
          setSession(null);
        }
      });
    };
    return () => {
      live = false;
      clearTimeout(timer);
      stream.close();
    };
  }, [session?.actor.subject, session?.expires]);
  useEffect(() => {
    document.title = `${nav.find((x) => x.id === path.split("/")[0])?.label || "Policy control"} · AgentGate`;
  }, [path]);
  if (session === null) return <Login />;
  if (!session)
    return (
      <main className="boot">
        {error ? <ErrorBox error={error} /> : <Loading />}
      </main>
    );
  const actor = session.actor;
  const perms = permissions(actor);
  const visibleNav = nav.filter(item => (item.id !== 'users' || (session.local_identity && actor.roles.includes('admin'))) && (item.id !== 'policy-builder' || session.customer_policy) && (item.id !== 'launch' || perms.launch) && (item.id !== 'secrets' || perms.secretsAdmin) && (item.id !== 'tokens' || perms.tokens));
  const section = path.split("/")[0];
  const parts = path.split("/");
  const expiresSoon = session.expires && session.expires * 1000 - clock < 5 * 60 * 1000;
  let content: React.ReactNode;
  switch (section) {
    case "targets":
      content = parts[1] ? <TargetDetail key={parts[1]} id={parts[1]} actor={actor} epoch={epoch} navigate={navigate} /> : <Targets actor={actor} epoch={epoch} navigate={navigate} />;
      break;
    case "profiles":
      content = parts[1] ? <ProfileDetail key={parts[1]} id={parts[1]} selected={parts[2] ? Number(parts[2]) : undefined} actor={actor} epoch={epoch} navigate={navigate} /> : <Profiles actor={actor} epoch={epoch} navigate={navigate} />;
      break;
    case "launch":
      content = <LaunchPage key={path} actor={actor} from={parts[1] === "from" ? parts[2] : undefined} navigate={navigate} />;
      break;
    case "launches":
      content = parts[1] ? <LaunchDetail key={parts[1]} id={parts[1]} actor={actor} epoch={epoch} navigate={navigate} /> : <Launches actor={actor} epoch={epoch} navigate={navigate} />;
      break;
    case "secrets":
      content = <Secrets actor={actor} epoch={epoch} />;
      break;
    case "tokens":
      content = <Tokens actor={actor} epoch={epoch} />;
      break;
    case "users":
      content = session.local_identity && actor.roles.includes('admin') ? <Users epoch={epoch} refresh={refresh} /> : <ErrorBox error={new Error('Local user administration requires an administrator.')} />;
      break;
    case "policy-builder":
      content = session.customer_policy ? <PolicyWorkspace key={path} actor={actor} parentID={path.split("/")[1]} navigate={navigate} refresh={refresh} /> : <ErrorBox error={new Error("The full policy builder requires the Community contract.")} />;
      break;
    case "policies":
      content = path.includes("/") ? (
        <PolicyDetail
          id={path.split("/")[1]}
          actor={actor}
          epoch={epoch}
          navigate={navigate}
          refresh={refresh}
        />
      ) : (
        <Policies
          actor={actor}
          epoch={epoch}
          navigate={navigate}
          refresh={refresh}
        />
      );
      break;
    case "requests":
      content = <Requests key={path} actor={actor} epoch={epoch} refresh={refresh} versionID={path.split("/")[1]} />;
      break;
    case "runs":
      content = path.includes("/") ? (
        <RunDetail id={path.split("/")[1]} epoch={epoch} navigate={navigate} />
      ) : (
        <Runs epoch={epoch} navigate={navigate} />
      );
      break;
    case "audit":
      content = <AuditExplorer key={path} epoch={epoch} actor={actor} versionID={path.split("/")[1]} />;
      break;
    default:
      content = <Overview epoch={epoch} navigate={navigate} extra={<ProvisioningOverview actor={actor} epoch={epoch} navigate={navigate} />} />;
  }
  return (
    <div className="app-shell">
      <a
        className="skip-link"
        href="#main-content"
        onClick={(event) => {
          event.preventDefault();
          document.getElementById("main-content")?.focus();
        }}
      >
        Skip to content
      </a>
      {mobile && (
        <button
          className="nav-overlay"
          aria-label="Close navigation"
          onClick={() => setMobile(false)}
        />
      )}
      <aside className={`sidebar ${mobile ? "open" : ""}`}>
        <a className="brand" href="#/overview">
          <ShieldCheck size={27} />
          <span>
            AgentGate<small>Policy control</small>
          </span>
        </a>
        <div className="workspace-tag">
          <span />
          Operator workspace
        </div>
        <nav aria-label="Main navigation">
          {visibleNav.map(({ id, label, icon: Icon }) => (
            <a
              href={`#/${id}`}
              key={id}
              className={section === id ? "active" : ""}
              aria-current={section === id ? "page" : undefined}
              onClick={() => setMobile(false)}
            >
              <Icon size={19} />
              {label}
            </a>
          ))}
        </nav>
        <div className="sidebar-foot">
          <ShieldCheck size={20} />
          <div>
            <strong>Versioned by design</strong>
            <p>History follows every policy decision.</p>
          </div>
        </div>
      </aside>
      <div className="workspace">
        <header className="topbar">
          <div>
            <button
              className="mobile-menu icon-button"
              aria-label="Open navigation"
              onClick={() => setMobile(!mobile)}
            >
              {mobile ? <X /> : <Menu />}
            </button>
            {session.fixture_label && (
              <span className="badge pending">Synthetic acceptance</span>
            )}
            <span>
              Control plane <span className="breadcrumb">/</span>{" "}
              {nav.find((n) => n.id === section)?.label || "Overview"}
            </span>
          </div>
          <div className="account">
            <span className="avatar">
              {actor.subject.slice(0, 2).toUpperCase()}
            </span>
            <div>
              <strong>{actor.name || actor.subject}</strong>
              <small>{actor.roles.join(" · ")}</small>
            </div>
            <button
              className="icon-button"
              aria-label="Sign out"
              onClick={async () => {
                try {
                  await api("/auth/logout", "POST", {});
                  setSession(null);
                } catch (e) {
                  setError(e);
                }
              }}
            >
              <LogOut size={18} />
            </button>
          </div>
        </header>
        <main id="main-content" tabIndex={-1}>
          {expiresSoon && (
            <div className="session-warning" role="status">
              Your session ends at {new Date(session.expires * 1000).toLocaleTimeString()}. Unsaved form input is lost when it does; sign in again to continue.
            </div>
          )}
          {Boolean(error) && <ErrorBox error={error} />} {content}
        </main>
        <footer className="workspace-footer">
          <span>Policy authority and execution evidence</span>
          <span>Private prototype · {packageInfo.version}</span>
        </footer>
      </div>
    </div>
  );
}
createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
