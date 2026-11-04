"use strict";

const fs = require("fs");
const path = require("path");
const { spawn } = require("child_process");
const vscode = require("vscode");

const SCOPE = ["https://management.azure.com/.default"];
const PROVIDER = "microsoft";
const COMMAND_TIMEOUT_MS = 180000;

/**
 * @param {vscode.ExtensionContext} context
 */
function activate(context) {
  const model = new OpsModel();
  const incidents = new IncidentTree(model);
  const blocks = new BlockTree(model);
  const incidentView = vscode.window.createTreeView("aseSentinel.incidents", { treeDataProvider: incidents });
  const blockView = vscode.window.createTreeView("aseSentinel.blocks", { treeDataProvider: blocks });
  const status = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
  status.command = "aseSentinel.signIn";
  status.show();

  const refreshViews = () => {
    incidents.refresh();
    blocks.refresh();
    incidentView.message = model.notice;
    blockView.message = model.notice;
    status.text = model.account
      ? `$(account) ${model.account}${model.subscription ? " · " + model.subscription : ""}`
      : "$(account) ASE Sentinel: Sign in";
    status.tooltip = model.subscription
      ? `Reads use subscription ${model.subscription}`
      : "Sign in, then pin the subscription, resource group, workspace, and WAF policy.";
  };

  context.subscriptions.push(
    incidentView,
    blockView,
    status,
    vscode.commands.registerCommand("aseSentinel.signIn", async () => {
      await model.signIn();
      refreshViews();
    }),
    vscode.commands.registerCommand("aseSentinel.refresh", async () => {
      await model.load(false);
      refreshViews();
    }),
    vscode.authentication.onDidChangeSessions(async (event) => {
      if (event.provider.id === PROVIDER) {
        await model.load(false);
        refreshViews();
      }
    }),
    vscode.workspace.onDidChangeConfiguration(async (event) => {
      const scope = configurationScope();
      const changed = scope
        ? event.affectsConfiguration("aseSentinel", scope)
        : event.affectsConfiguration("aseSentinel");
      if (changed) {
        await model.load(false);
        refreshViews();
      }
    })
  );

  model.load(false).then(refreshViews);
}

class OpsModel {
  constructor() {
    this.incidents = [];
    this.rules = [];
    this.error = "";
    this.notice = "";
    this.account = "";
    this.subscription = "";
    this.loading = false;
    this.generation = 0;
  }

  async signIn() {
    await vscode.authentication.getSession(PROVIDER, SCOPE, { createIfNone: true });
    await this.load(false);
  }

  async load(createSession) {
    const generation = ++this.generation;
    this.loading = false;
    const pinned = readPinned();
    this.subscription = pinned.subscriptionId || "";
    if (pinned.error) {
      this.incidents = [];
      this.rules = [];
      this.error = pinned.error;
      this.notice = "";
      return;
    }
    let session;
    try {
      session = await vscode.authentication.getSession(
        PROVIDER,
        SCOPE,
        createSession ? { createIfNone: true } : { silent: true }
      );
    } catch {
      this.error = "Microsoft sign-in is unavailable in this VS Code window.";
      this.notice = "";
      this.incidents = [];
      this.rules = [];
      return;
    }
    if (generation !== this.generation) {
      return;
    }
    if (!session || !session.accessToken) {
      this.account = "";
      this.incidents = [];
      this.rules = [];
      this.error = "Sign in to read Sentinel.";
      this.notice = "";
      return;
    }
    this.account = session.account.label;
    this.error = "";
    this.loading = true;
    this.notice = "";
    try {
      const [listed, inventory] = await Promise.all([
        runOps(pinned, session.accessToken, ["list"]),
        runOps(pinned, session.accessToken, ["inventory"]),
      ]);
      if (generation !== this.generation) {
        return;
      }
      this.incidents = Array.isArray(listed.incidents) ? listed.incidents : [];
      const policy = Array.isArray(inventory.policies) ? inventory.policies[0] : undefined;
      this.rules = policy && Array.isArray(policy.rules) ? policy.rules : [];
      this.notice = inventory.gatewayError ? String(inventory.gatewayError) : "";
      this.error = "";
    } catch (error) {
      if (generation !== this.generation) {
        return;
      }
      this.incidents = [];
      this.rules = [];
      this.notice = "";
      this.error = error instanceof Error ? error.message : "the Azure call failed";
    } finally {
      if (generation === this.generation) {
        this.loading = false;
      }
    }
  }
}

class IncidentTree {
  constructor(model) {
    this.model = model;
    this.emitter = new vscode.EventEmitter();
    this.onDidChangeTreeData = this.emitter.event;
  }

  refresh() {
    this.emitter.fire();
  }

  getTreeItem(element) {
    return element;
  }

  getChildren() {
    if (this.model.error) {
      return [note(this.model.error, this.model.account ? undefined : "aseSentinel.signIn")];
    }
    if (this.model.loading && this.model.incidents.length === 0) {
      return [note("Loading…")];
    }
    if (this.model.incidents.length === 0) {
      return [note("No open incidents.")];
    }
    return this.model.incidents.map((incident) => incidentItem(incident));
  }
}

class BlockTree {
  constructor(model) {
    this.model = model;
    this.emitter = new vscode.EventEmitter();
    this.onDidChangeTreeData = this.emitter.event;
  }

  refresh() {
    this.emitter.fire();
  }

  getTreeItem(element) {
    return element;
  }

  getChildren(element) {
    if (!element) {
      if (this.model.error) {
        return [note(this.model.error, this.model.account ? undefined : "aseSentinel.signIn")];
      }
      if (this.model.loading && this.model.rules.length === 0) {
        return [note("Loading…")];
      }
      if (this.model.rules.length === 0) {
        return [note("No SentinelAutoBlock entries.")];
      }
      return this.model.rules.map((rule) => ruleItem(rule));
    }
    return (element.addresses || []).map((value) => addressItem(value));
  }
}

function incidentItem(incident) {
  const ips = Array.isArray(incident.ips) && incident.ips.length ? incident.ips.join(", ") : "no IPv4";
  const item = new vscode.TreeItem(
    `#${incident.number || "?"} ${incident.title || "incident"}`,
    vscode.TreeItemCollapsibleState.None
  );
  item.description = ips;
  item.tooltip = [incident.severity, incident.status, incident.created, ips].filter(Boolean).join("\n");
  item.id = String(incident.id || incident.number || "");
  item.contextValue = "incident";
  return item;
}

function ruleItem(rule) {
  const values = Array.isArray(rule.values) ? rule.values : [];
  const item = new vscode.TreeItem(String(rule.name || "rule"), vscode.TreeItemCollapsibleState.Expanded);
  item.description = `${values.length}`;
  item.addresses = values;
  item.contextValue = "blockRule";
  return item;
}

function addressItem(value) {
  const item = new vscode.TreeItem(String(value), vscode.TreeItemCollapsibleState.None);
  item.contextValue = "blockAddress";
  return item;
}

function note(text, command) {
  const item = new vscode.TreeItem(text, vscode.TreeItemCollapsibleState.None);
  if (command) {
    item.command = { command, title: "Sign in" };
  }
  return item;
}

function configurationScope() {
  const folders = vscode.workspace.workspaceFolders;
  return folders && folders.length ? folders[0].uri : null;
}

function readPinned() {
  const config = vscode.workspace.getConfiguration("aseSentinel", configurationScope());
  const subscriptionId = stringSetting(config, "subscriptionId");
  const resourceGroup = stringSetting(config, "resourceGroup");
  const workspaceName = stringSetting(config, "workspaceName");
  const wafPolicyResourceId = stringSetting(config, "wafPolicyResourceId");
  const missing = [
    ["aseSentinel.subscriptionId", subscriptionId],
    ["aseSentinel.resourceGroup", resourceGroup],
    ["aseSentinel.workspaceName", workspaceName],
    ["aseSentinel.wafPolicyResourceId", wafPolicyResourceId],
  ]
    .filter(([, value]) => !value)
    .map(([name]) => name);
  if (missing.length) {
    return { error: "Set " + missing.join(", ") + "." };
  }
  const webappPath = resolveWebapp(stringSetting(config, "webappPath"));
  if (!webappPath) {
    return { error: "Set aseSentinel.webappPath to the repo webapp directory." };
  }
  const pythonPath = resolvePython(webappPath, stringSetting(config, "pythonPath"));
  if (!pythonPath) {
    return { error: "Set aseSentinel.pythonPath to a Python that can import this repo." };
  }
  return { subscriptionId, resourceGroup, workspaceName, wafPolicyResourceId, webappPath, pythonPath };
}

function stringSetting(config, name) {
  const value = config.get(name);
  return typeof value === "string" ? value.trim() : "";
}

function resolveWebapp(configured) {
  if (configured && fs.existsSync(path.join(configured, "ase_sentinel_ops", "__main__.py"))) {
    return configured;
  }
  const folders = vscode.workspace.workspaceFolders || [];
  for (const folder of folders) {
    const direct = path.join(folder.uri.fsPath, "webapp");
    if (fs.existsSync(path.join(direct, "ase_sentinel_ops", "__main__.py"))) {
      return direct;
    }
    const sibling = path.resolve(folder.uri.fsPath, "..", "webapp");
    if (fs.existsSync(path.join(sibling, "ase_sentinel_ops", "__main__.py"))) {
      return sibling;
    }
  }
  return "";
}

function resolvePython(webappPath, configured) {
  if (configured && fs.existsSync(configured)) {
    return configured;
  }
  for (const parts of [["Scripts", "python.exe"], ["bin", "python"]]) {
    const venv = path.join(webappPath, ".venv", ...parts);
    if (fs.existsSync(venv)) {
      return venv;
    }
  }
  return "";
}

function runOps(pinned, token, args) {
  return new Promise((resolve, reject) => {
    const child = spawn(pinned.pythonPath, ["-m", "ase_sentinel_ops", ...args], {
      cwd: pinned.webappPath,
      shell: false,
      windowsHide: true,
      env: childEnv(pinned),
      stdio: ["pipe", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    const timer = setTimeout(() => {
      child.kill();
      reject(new Error("the operations command timed out"));
    }, COMMAND_TIMEOUT_MS);
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => {
      stdout += chunk;
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk;
    });
    child.on("error", (error) => {
      clearTimeout(timer);
      reject(new Error(redact(error.message, token)));
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      const parsed = parseOps(stdout, token);
      if (parsed && code === 0 && !parsed.error) {
        resolve(parsed);
        return;
      }
      const message =
        (parsed && parsed.error) ||
        redact(stderr, token).trim() ||
        "the operations command failed";
      reject(new Error(message));
    });
    child.stdin.write(token + "\n");
    child.stdin.end();
  });
}

function childEnv(pinned) {
  const env = { ...process.env, PYTHONPATH: pinned.webappPath };
  env.AZURE_SUBSCRIPTION_ID = pinned.subscriptionId;
  env.AZURE_RESOURCE_GROUP = pinned.resourceGroup;
  env.SENTINEL_WORKSPACE_NAME = pinned.workspaceName;
  env.WAF_POLICY_RESOURCE_ID = pinned.wafPolicyResourceId;
  for (const name of [
    "BLOCK_API_KEY",
    "APP_SECRET",
    "DEV_LOGIN_PASSWORD",
    "AZURE_CLIENT_SECRET",
    "AZURE_CLIENT_CERTIFICATE_PATH",
    "AZURE_CLIENT_CERTIFICATE_PASSWORD",
  ]) {
    delete env[name];
  }
  return env;
}

function parseOps(stdout, token) {
  const text = redact(stdout, token).trim();
  if (!text) {
    return undefined;
  }
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
  }
}

function redact(text, token) {
  if (!text || !token) {
    return text || "";
  }
  return String(text).split(token).join("[redacted]");
}

function deactivate() {}

module.exports = { activate, deactivate };
