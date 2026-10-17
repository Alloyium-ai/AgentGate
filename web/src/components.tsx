// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf

import React, { useEffect, useId, useRef } from "react";
import {
  Check,
  ChevronRight,
  AlertTriangle,
  Lock,
  ArrowRight,
  ShieldCheck,
  LoaderCircle,
  X,
} from "lucide-react";
import { ApiError, Rights } from "./api";
export function Badge({ value }: { value: string }) {
  const labels: Record<string, string> = {
    VALID_COMPLETE: "Valid complete",
    INCOMPLETE: "Incomplete",
    TAMPERED: "Integrity failed",
    UNKNOWN_KEY: "Unknown key",
  };
  return (
    <span className={`badge ${value.toLowerCase()}`}>
      {labels[value] || value.replaceAll("_", " ")}
    </span>
  );
}
export function Empty({
  title,
  text,
  action,
}: {
  title: string;
  text: string;
  action?: React.ReactNode;
}) {
  return (
    <div className="empty">
      <ShieldCheck size={30} />
      <h3>{title}</h3>
      <p>{text}</p>
      {action}
    </div>
  );
}
export function Loading() {
  return (
    <div className="loading" role="status">
      <LoaderCircle className="spin" size={20} /> Loading records…
    </div>
  );
}
export function ErrorBox({ error }: { error: unknown }) {
  const e = error as ApiError;
  return (
    <div className="error-box" role="alert">
      <AlertTriangle size={19} />
      <div>
        <strong>
          {e?.status === 403
            ? "Access is restricted"
            : e?.status === 412
              ? "The record changed"
              : "The request did not complete"}
        </strong>
        <p>{e?.message || "Refresh the page and try again."}</p>
        {e?.requestID && <small>Request {e.requestID}</small>}
      </div>
    </div>
  );
}
export function RightsView({ rights }: { rights: Rights }) {
  return (
    <div className="rights">
      <span className={rights.workspace_write ? "enabled" : ""}>
        {rights.workspace_write ? <Check size={16} /> : <Lock size={16} />}{" "}
        {rights.workspace_write
          ? "Selected existing-file write opens allowed"
          : "Selected existing-file write opens denied"}
      </span>
      <span>
        <ArrowRight size={16} /> IPv4 TCP target{" "}
        <small>{rights.tcp_address}:{rights.tcp_port}</small>
      </span>
    </div>
  );
}
export function Diff({ before, after }: { before?: Rights; after: Rights }) {
  const rows = [
    [
      "Existing-file write opens",
      before?.workspace_write ? "Allow" : "Deny",
      after.workspace_write ? "Allow" : "Deny",
    ],
    [
      "IPv4 TCP target",
      before ? `${before.tcp_address}:${before.tcp_port}` : "—",
      `${after.tcp_address}:${after.tcp_port}`,
    ],
  ];
  return (
    <div className="diff">
      {rows.map(([name, old, next]) => (
        <div key={name}>
          <span>{name}</span>
          <div>
            <span className="old-value">{before ? old : "New policy"}</span>
            <ChevronRight size={14} />
            <strong className={before && old !== next ? "changed" : ""}>
              {next}
            </strong>
          </div>
        </div>
      ))}
    </div>
  );
}
export function Modal({
  title,
  onClose,
  children,
}: {
  title: string;
  onClose: () => void;
  children: React.ReactNode;
}) {
  const ref = useRef<HTMLDialogElement>(null);
  const titleId = useId();
  useEffect(() => {
    ref.current?.showModal();
    return () => ref.current?.close();
  }, []);
  return (
    <dialog
      ref={ref}
      aria-labelledby={titleId}
      onCancel={(e) => {
        e.preventDefault();
        onClose();
      }}
    >
      <div className="modal-heading">
        <h2 id={titleId}>{title}</h2>
        <button
          className="icon-button"
          aria-label="Close dialog"
          onClick={onClose}
        >
          <X size={20} />
        </button>
      </div>
      {children}
    </dialog>
  );
}
export function Pager({
  next,
  onNext,
  onBack,
  back,
}: {
  next?: string;
  onNext: (cursor: string) => void;
  onBack: () => void;
  back: boolean;
}) {
  return (
    <div className="pager">
      <button className="secondary" disabled={!back} onClick={onBack}>
        Previous
      </button>
      <span>Up to 50 records per page</span>
      <button
        className="secondary"
        disabled={!next}
        onClick={() => next && onNext(next)}
      >
        Next <ChevronRight size={14} />
      </button>
    </div>
  );
}
export function SectionTitle({
  eyebrow,
  title,
  text,
  action,
}: {
  eyebrow: string;
  title: string;
  text: string;
  action?: React.ReactNode;
}) {
  return (
    <div className="section-title">
      <div>
        <p className="eyebrow">{eyebrow}</p>
        <h1>{title}</h1>
        <p>{text}</p>
      </div>
      {action}
    </div>
  );
}
