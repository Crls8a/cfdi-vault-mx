"use client";

import { useEffect, useState } from "react";
import {
  ApiError,
  CampaignRecord,
  CampaignRunQueuedResponse,
  DockerServiceStatus,
  getCampaignStatus,
  getDockerServices,
  getHealth,
  getProfileStatus,
  runCampaign,
  startDockerService,
  stopDockerService,
} from "@/lib/api";

const POLL_INTERVAL_MS = 5000;

export default function Dashboard() {
  return (
    <div className="min-h-screen bg-zinc-50 px-6 py-10 text-zinc-900 dark:bg-black dark:text-zinc-50">
      <div className="mx-auto flex max-w-3xl flex-col gap-8">
        <header className="flex items-center justify-between">
          <h1 className="text-2xl font-semibold">cfdi-vault-mx control panel</h1>
          <HealthIndicator />
        </header>

        <ProfileStatusCard />
        <CampaignCard />
        <DockerServicesCard />
      </div>
    </div>
  );
}

function HealthIndicator() {
  const [connected, setConnected] = useState<boolean | null>(null);

  useEffect(() => {
    let cancelled = false;

    const check = () => {
      getHealth()
        .then((res) => {
          if (!cancelled) setConnected(res.status === "ok");
        })
        .catch(() => {
          if (!cancelled) setConnected(false);
        });
    };

    check();
    const interval = setInterval(check, POLL_INTERVAL_MS);
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, []);

  const label =
    connected === null ? "checking..." : connected ? "connected" : "disconnected";
  const color =
    connected === null
      ? "bg-zinc-400"
      : connected
        ? "bg-green-500"
        : "bg-red-500";

  return (
    <div className="flex items-center gap-2 text-sm">
      <span className={`h-2.5 w-2.5 rounded-full ${color}`} />
      <span className="text-zinc-600 dark:text-zinc-400">{label}</span>
    </div>
  );
}

function Section({
  title,
  children,
}: {
  title: string;
  children: React.ReactNode;
}) {
  return (
    <section className="rounded-lg border border-zinc-200 bg-white p-5 dark:border-zinc-800 dark:bg-zinc-950">
      <h2 className="mb-4 text-lg font-medium">{title}</h2>
      {children}
    </section>
  );
}

function ProfileStatusCard() {
  const [profileId, setProfileId] = useState("");
  const [status, setStatus] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleProfileIdChange = (value: string) => {
    setProfileId(value);
    if (!value) {
      setStatus(null);
      setError(null);
    }
  };

  useEffect(() => {
    if (!profileId) {
      return;
    }

    let cancelled = false;

    const fetchStatus = () => {
      getProfileStatus(profileId)
        .then((res) => {
          if (cancelled) return;
          setStatus(res.status);
          setError(null);
        })
        .catch((err: unknown) => {
          if (cancelled) return;
          setStatus(null);
          setError(err instanceof ApiError ? err.message : "request failed");
        });
    };

    fetchStatus();
    const interval = setInterval(fetchStatus, POLL_INTERVAL_MS);
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, [profileId]);

  return (
    <Section title="Profile status">
      <label
        htmlFor="profile-status-id"
        className="mb-1 block text-sm text-zinc-600 dark:text-zinc-400"
      >
        Profile ID
      </label>
      <input
        id="profile-status-id"
        className="mb-4 w-full rounded border border-zinc-300 bg-transparent px-3 py-2 text-sm dark:border-zinc-700"
        placeholder="profile id"
        value={profileId}
        onChange={(e) => handleProfileIdChange(e.target.value)}
      />
      {error && <p className="text-sm text-red-500">{error}</p>}
      {status && (
        <pre className="whitespace-pre-wrap rounded bg-zinc-100 p-3 text-sm dark:bg-zinc-900">
          {status}
        </pre>
      )}
    </Section>
  );
}

function CampaignCard() {
  const [profileId, setProfileId] = useState("");
  const [campaignRef, setCampaignRef] = useState("");
  const [grant, setGrant] = useState("");
  const [statusResult, setStatusResult] = useState<CampaignRecord | null>(null);
  const [runResult, setRunResult] = useState<CampaignRunQueuedResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [running, setRunning] = useState(false);

  const handleProfileIdChange = (value: string) => {
    setProfileId(value);
    if (!value || !campaignRef) {
      setStatusResult(null);
    }
  };

  const handleCampaignRefChange = (value: string) => {
    setCampaignRef(value);
    if (!value || !profileId) {
      setStatusResult(null);
    }
  };

  useEffect(() => {
    if (!profileId || !campaignRef) {
      return;
    }

    let cancelled = false;

    const fetchStatus = () => {
      getCampaignStatus(profileId, campaignRef)
        .then((res) => {
          if (cancelled) return;
          setStatusResult(res);
          setError(null);
        })
        .catch((err: unknown) => {
          if (cancelled) return;
          setStatusResult(null);
          setError(err instanceof ApiError ? err.message : "request failed");
        });
    };

    fetchStatus();
    const interval = setInterval(fetchStatus, POLL_INTERVAL_MS);
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, [profileId, campaignRef]);

  const handleRun = async () => {
    if (!profileId || !campaignRef || !grant) return;
    setRunning(true);
    setError(null);
    setRunResult(null);
    try {
      const result = await runCampaign(profileId, campaignRef, grant);
      setRunResult(result);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "request failed");
    } finally {
      setRunning(false);
    }
  };

  return (
    <Section title="Campaign">
      <div className="mb-4 grid grid-cols-1 gap-3 sm:grid-cols-2">
        <div>
          <label
            htmlFor="campaign-profile-id"
            className="mb-1 block text-sm text-zinc-600 dark:text-zinc-400"
          >
            Profile ID
          </label>
          <input
            id="campaign-profile-id"
            className="w-full rounded border border-zinc-300 bg-transparent px-3 py-2 text-sm dark:border-zinc-700"
            placeholder="profile id"
            value={profileId}
            onChange={(e) => handleProfileIdChange(e.target.value)}
          />
        </div>
        <div>
          <label
            htmlFor="campaign-ref"
            className="mb-1 block text-sm text-zinc-600 dark:text-zinc-400"
          >
            Campaign ref
          </label>
          <input
            id="campaign-ref"
            className="w-full rounded border border-zinc-300 bg-transparent px-3 py-2 text-sm dark:border-zinc-700"
            placeholder="campaign ref"
            value={campaignRef}
            onChange={(e) => handleCampaignRefChange(e.target.value)}
          />
        </div>
      </div>

      {statusResult && (
        <dl className="mb-4 divide-y divide-zinc-200 rounded border border-zinc-200 text-sm dark:divide-zinc-800 dark:border-zinc-800">
          {Object.entries(statusResult).map(([key, value]) => (
            <div key={key} className="flex justify-between gap-4 px-3 py-2">
              <dt className="font-medium text-zinc-600 dark:text-zinc-400">
                {key}
              </dt>
              <dd className="text-right break-all">
                {typeof value === "object" ? JSON.stringify(value) : String(value)}
              </dd>
            </div>
          ))}
        </dl>
      )}

      <div className="mb-3 flex items-end gap-3">
        <div className="flex-1">
          <label
            htmlFor="campaign-grant"
            className="mb-1 block text-sm text-zinc-600 dark:text-zinc-400"
          >
            Grant
          </label>
          <input
            id="campaign-grant"
            className="w-full rounded border border-zinc-300 bg-transparent px-3 py-2 text-sm dark:border-zinc-700"
            placeholder="grant"
            value={grant}
            onChange={(e) => setGrant(e.target.value)}
          />
        </div>
        <button
          type="button"
          className="rounded bg-zinc-900 px-4 py-2 text-sm font-medium text-white disabled:opacity-50 dark:bg-zinc-100 dark:text-zinc-900"
          disabled={running || !profileId || !campaignRef || !grant}
          onClick={handleRun}
        >
          {running ? "Queuing..." : "Run"}
        </button>
      </div>

      {error && <p className="text-sm text-red-500">{error}</p>}

      {runResult && (
        <div className="rounded bg-zinc-100 p-3 text-sm dark:bg-zinc-900">
          <p>
            Queued as <span className="font-mono">{runResult.run_ref}</span> at{" "}
            {runResult.requested_at}.
          </p>
          <p className="mt-1 text-zinc-500">
            The live SAT sequence runs out of process — check{" "}
            <span className="font-mono">last_run</span> in the status above for
            the outcome.
          </p>
        </div>
      )}
    </Section>
  );
}

function DockerServicesCard() {
  const [services, setServices] = useState<DockerServiceStatus[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState<string | null>(null);

  const refresh = () => {
    getDockerServices()
      .then((res) => {
        setServices(res);
        setError(null);
      })
      .catch((err: unknown) => {
        setError(err instanceof ApiError ? err.message : "request failed");
      });
  };

  useEffect(() => {
    refresh();
    const interval = setInterval(refresh, POLL_INTERVAL_MS);
    return () => clearInterval(interval);
  }, []);

  const handleAction = async (service: string, action: "start" | "stop") => {
    setPending(`${service}:${action}`);
    setError(null);
    try {
      if (action === "start") {
        await startDockerService(service);
      } else {
        await stopDockerService(service);
      }
      refresh();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "request failed");
    } finally {
      setPending(null);
    }
  };

  return (
    <Section title="Docker services">
      {error && <p className="mb-3 text-sm text-red-500">{error}</p>}
      <ul className="divide-y divide-zinc-200 rounded border border-zinc-200 text-sm dark:divide-zinc-800 dark:border-zinc-800">
        {services.map((svc) => (
          <li
            key={svc.service}
            className="flex items-center justify-between gap-4 px-3 py-2"
          >
            <div>
              <span className="font-medium">{svc.service}</span>
              <span className="ml-2 text-zinc-500">{svc.state}</span>
            </div>
            <div className="flex gap-2">
              <button
                type="button"
                className="rounded border border-zinc-300 px-3 py-1 text-xs font-medium disabled:opacity-50 dark:border-zinc-700"
                disabled={pending === `${svc.service}:start`}
                onClick={() => handleAction(svc.service, "start")}
              >
                Start
              </button>
              <button
                type="button"
                className="rounded border border-zinc-300 px-3 py-1 text-xs font-medium disabled:opacity-50 dark:border-zinc-700"
                disabled={pending === `${svc.service}:stop`}
                onClick={() => handleAction(svc.service, "stop")}
              >
                Stop
              </button>
            </div>
          </li>
        ))}
      </ul>
    </Section>
  );
}
