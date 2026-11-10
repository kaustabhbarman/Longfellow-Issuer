const params = new URLSearchParams(window.location.search);
const configId = params.get("config_id");
const urlSchema = params.get("url_schema") || "openid-credential-offer";

// Only show the two credential types selected for the Issuer UI.
// Keep the other credential factories and backend functionality intact.
const VISIBLE_CREDENTIALS = [
    { id: "mDL", title: "Driving Licence", description: "Issue a digital driving licence." },
    { id: "pid_mdoc", title: "Personal ID", description: "Issue a digital personal identity credential." }
];

if (configId) {
    displayCredentialConfig(configId);
} else {
    displayCredentialList();
}

function element(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
}

function addText(parent, tag, className, text) {
    const node = element(tag, className, text);
    parent.appendChild(node);
    return node;
}

async function fetchMetadata() {
    const path = location.pathname.substring(0, location.pathname.lastIndexOf("/"));
    const response = await fetch("/.well-known/openid-credential-issuer" + path);
    if (!response.ok) throw new Error("Issuer metadata could not be loaded.");
    return response.json();
}

function addHeader(issuance) {
    const container = document.getElementById("main");
    const header = element("header", "site-header");

    const identity = element("div", "issuer-identity");
    const issuerLogo = issuance.display?.[0]?.logo?.uri;

    if (issuerLogo) {
        const img = element("img", "issuer-logo");
        img.src = issuerLogo;
        img.alt = "Issuer logo";
        identity.appendChild(img);
    }

    const text = element("div", "issuer-identity-text");
    addText(text, "p", "eyebrow", "DIGITAL CREDENTIAL ISSUANCE");
    addText(text, "h1", "issuer-name", issuance.display?.[0]?.name || "Digital Credential Issuer");
    identity.appendChild(text);
    header.appendChild(identity);

    const back = element("a", "text-link", "All credentials");
    back.href = location.pathname;
    if (configId) header.appendChild(back);

    container.appendChild(header);
}

function createCredentialLink(configId, schema) {
    const baseUrl = location.href.replace(/\?.*/, "");
    return baseUrl + "?config_id=" + encodeURIComponent(configId) +
        "&url_schema=" + encodeURIComponent(schema);
}

async function displayCredentialList() {
    const container = document.getElementById("main");

    try {
        const issuance = await fetchMetadata();
        addHeader(issuance);

        const section = element("section", "page-intro");
        addText(section, "p", "eyebrow", "CREDENTIAL CATALOGUE");
        addText(section, "h2", "page-title", "Choose a credential");
        addText(section, "p", "page-description",
            "Select the credential you want to issue and configure its offer.");
        container.appendChild(section);

        const grid = element("div", "credential-grid");
        container.appendChild(grid);

        for (const item of VISIBLE_CREDENTIALS) {
            const config = issuance.credential_configurations_supported?.[item.id];
            if (!config) {
                console.warn("Credential configuration unavailable:", item.id);
                continue;
            }

            const display = config.credential_metadata?.display?.[0] || {};
            const card = element("a", "credential-card");
            card.href = createCredentialLink(item.id, urlSchema);
            card.setAttribute("aria-label", "Configure " + item.title);

            const imageFrame = element("div", "credential-card-art");
            const img = element("img", "credential-list-art");
            img.src = (item.id === "mDL" ? "card-mdl.png" : "card-pid.png");
            img.alt = item.title + " card artwork";
            img.loading = "lazy";
            imageFrame.appendChild(img);
            card.appendChild(imageFrame);

            const content = element("div", "credential-card-content");
            addText(content, "h3", "credential-card-title", item.title);
            addText(content, "p", "credential-card-description", item.description);
            addText(content, "span", "card-action", "Configure issuance →");
            card.appendChild(content);
            grid.appendChild(card);
        }

        if (!grid.children.length) {
            addText(container, "p", "status-message",
                "The selected credential configurations are not available in issuer metadata.");
        }
    } catch (error) {
        showError(container, error);
    }
}

async function displayCredentialConfig(id) {
    const container = document.getElementById("main");

    try {
        const issuance = await fetchMetadata();
        const selected = VISIBLE_CREDENTIALS.find(item => item.id === id);
        const config = issuance.credential_configurations_supported?.[id];

        addHeader(issuance);

        if (!selected || !config) {
            showError(container, new Error("This credential is not available in the current catalogue."));
            return;
        }

        const display = config.credential_metadata?.display?.[0] || {};
        const page = element("section", "detail-page");

        const intro = element("div", "detail-intro");
        addText(intro, "p", "eyebrow", "CREDENTIAL CONFIGURATION");
        addText(intro, "h2", "page-title", selected.title);
        addText(intro, "p", "page-description", selected.description);
        page.appendChild(intro);

        const overview = element("div", "detail-overview");
        const art = element("div", "detail-art");
        const img = element("img", "credential-detail-art");
        img.src = (id === "mDL" ? "card-mdl.png" : "card-pid.png");
        img.alt = selected.title + " card artwork";
        art.appendChild(img);
        overview.appendChild(art);

        const meta = element("div", "detail-meta");
        addText(meta, "h3", "section-title", "Credential information");

        let formatText = config.format || "Not specified";
        if (config.format === "mso_mdoc") {
            formatText = "Mobile document (mDoc)";
            if (config.doctype) formatText += " · " + config.doctype;
        } else if (config.format === "dc+sd-jwt") {
            formatText = "SD-JWT";
            if (config.vct) formatText += " · " + config.vct;
        }

        addText(meta, "p", "meta-row", "Format: " + formatText);
        addText(meta, "p", "meta-row", "Configuration ID: " + id);
        overview.appendChild(meta);
        page.appendChild(overview);


        const preAuth = element("section", "panel");
        addText(preAuth, "h3", "section-title", "Create a pre-authorized offer");
        addText(preAuth, "p", "section-description",
            "Choose whether the recipient must enter a transaction code to receive the credential.");

        const form = element("form", "issuance-form");
        form.method = "GET";
        form.action = "authorize";

        addHidden(form, "configuration_id", id);
        addHidden(form, "url_schema", urlSchema);
        addHidden(form, "request_uri", "https://pre-authorize.multipaz.org/");

        const kindLabel = addText(form, "label", "form-label", "Transaction-code requirement");
        const kind = element("select", "form-control");
        kind.name = "tx_kind";
        kind.id = "tx_kind";
        kindLabel.htmlFor = "tx_kind";

        [
            ["none", "No transaction code"],
            ["n4", "4-digit code"],
            ["a4", "4-character alphanumeric code"],
            ["n6", "6-digit code"],
            ["a6", "6-character alphanumeric code"]
        ].forEach(([value, label]) => {
            const option = element("option", "", label);
            option.value = value;
            kind.appendChild(option);
        });
        form.appendChild(kindLabel);
        form.appendChild(kind);



        const submit = element("button", "button button-primary", "Generate pre-authorized offer");
        submit.type = "submit";
        form.appendChild(submit);
        preAuth.appendChild(form);
        page.appendChild(preAuth);

        const issuerUrl = location.href.substring(0, location.href.lastIndexOf("/"));
        const certificate = element("section", "panel certificate-panel");
        addText(certificate, "h3", "section-title", "Credential signing certificate");
        addText(certificate, "p", "section-description",
            "View the signing certificate associated with this credential configuration.");

        const certLink = element("a", "text-link", "View root certificate (PEM)");
        certLink.href = issuerUrl + "/signing_certificate?credential_id=" +
            encodeURIComponent(id);
        certificate.appendChild(certLink);
        page.appendChild(certificate);

        container.appendChild(page);
    } catch (error) {
        showError(container, error);
    }
}

function addHidden(form, name, value) {
    const input = element("input");
    input.type = "hidden";
    input.name = name;
    input.value = value;
    form.appendChild(input);
}

function showError(container, error) {
    console.error(error);
    const message = element("div", "error-panel");
    addText(message, "h2", "", "Unable to load this page");
    addText(message, "p", "", error.message || "An unexpected error occurred.");
    container.appendChild(message);
}
