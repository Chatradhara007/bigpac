// BigPAC web demo (v2): replays REAL held-out flows and classifies them with the v2 model.
const NAMES = {"youtube": "YouTube", "spotify": "Spotify", "instagram": "Instagram",
    "facebook-web": "Facebook", "whatsapp": "WhatsApp", "snapchat": "Snapchat",
    "discord": "Discord", "google-play": "Google Play", "tiktok": "TikTok",
    "microsoft-outlook": "Outlook", "other": "Other traffic", "any": "Random", "UNKNOWN": "UNKNOWN"};
const $ = id => document.getElementById(id);
let selected = null;

function pct(x) { return x == null ? "n/a" : (x * 100).toFixed(1) + "%"; }

fetch("/apps").then(r => r.json()).then(apps => {
    const keys = Object.keys(apps).concat(["any"]);
    keys.forEach(k => {
        const b = document.createElement("button");
        b.className = "app-btn";
        b.textContent = (NAMES[k] || k) + (apps[k] ? ` (${apps[k]})` : "");
        b.onclick = () => {
            document.querySelectorAll(".app-btn").forEach(x => x.classList.remove("active"));
            b.classList.add("active");
            selected = k;
            $("analyzeBtn").disabled = false;
        };
        $("appSelector").appendChild(b);
    });
});

fetch("/results").then(r => r.json()).then(m => {
    const n = m.new_heldout, o = m.old_heldout;
    let h = `<table class="metrics"><tr><th>Measurement</th><th>Known apps</th><th>All traffic</th></tr>`;
    h += `<tr><td>Old model, CESNET test (as originally reported)</td><td>${pct(m.cesnet_reported_old)}</td><td>—</td></tr>`;
    if (o) h += `<tr><td>Old model, held-out live session</td><td>${pct(o.known_accuracy)}</td><td>${pct(o.open_accuracy)}</td></tr>`;
    if (n) h += `<tr class="hl"><td><b>New model (v2), held-out live session</b></td><td><b>${pct(n.known_accuracy)}</b></td><td><b>${pct(n.open_accuracy)}</b></td></tr>`;
    if (m.new_cesnet_test) h += `<tr><td>New model (v2), CESNET test split</td><td>${pct(m.new_cesnet_test.accuracy)}</td><td>—</td></tr>`;
    h += `</table><p class="note">"Known apps" = connections of the 10 target apps. "All traffic" also counts
          connections to other services, which the model should label "other". Held-out session:
          ${(m.test_source || []).join(", ")}.</p>`;
    $("metrics").innerHTML = h;
}).catch(() => { $("metrics").textContent = "results not found - run train_v2.py"; });

function animate(pkts, done) {
    const s = $("packetStream");
    s.innerHTML = "";
    let i = 0;
    const show = pkts.slice(0, 30);
    const t = setInterval(() => {
        if (i >= show.length) { clearInterval(t); setTimeout(done, 300); return; }
        const [size, dir] = show[i];
        const d = document.createElement("div");
        d.className = "packet";
        d.style.height = `${Math.max(8, size / 1500 * 100)}%`;
        d.style.backgroundColor = dir === -1 ? "var(--primary)" : "var(--accent-1)";
        s.appendChild(d);
        i++;
    }, 60);
}

$("analyzeBtn").onclick = () => {
    if (!selected) return;
    $("analyzeBtn").disabled = true;
    ["predictionText", "confidenceValue", "truth", "topClasses"].forEach(id => $(id).innerHTML = "");
    $("confContainer").style.display = "none";
    $("loader").style.display = "block";
    fetch(`/get_sample/${selected}`).then(r => r.json()).then(flow => {
        if (flow.error) throw new Error(flow.error);
        animate(flow.packets, () => {
            fetch("/predict", {method: "POST", headers: {"Content-Type": "application/json"},
                               body: JSON.stringify({packets: flow.packets})})
            .then(r => r.json()).then(res => {
                $("loader").style.display = "none";
                $("analyzeBtn").disabled = false;
                if (res.error) { $("predictionText").textContent = res.error; return; }
                $("predictionText").textContent = NAMES[res.prediction] || res.prediction;
                const c = (res.confidence * 100).toFixed(1);
                $("confContainer").style.display = "block";
                setTimeout(() => { $("confidenceBar").style.width = `${c}%`; }, 50);
                $("confidenceValue").textContent = `${c}% confidence` +
                    (res.prediction === "UNKNOWN" ? ` (below threshold ${res.threshold})` : "");
                const ok = res.prediction === flow.label ||
                           (res.prediction === "UNKNOWN" && flow.label === "other");
                $("truth").innerHTML = `<span class="${ok ? "ok" : "bad"}">${ok ? "✓ correct" : "✗ wrong"}</span>
                    &nbsp;true app: <b>${NAMES[flow.label] || flow.label}</b><br>
                    <small>server name (label source, not used by the model): ${flow.sni}</small>`;
                res.top_3.forEach(it => {
                    const row = document.createElement("div");
                    row.className = "class-row";
                    row.innerHTML = `<span>${NAMES[it.class] || it.class}</span><span>${(it.prob * 100).toFixed(1)}%</span>`;
                    $("topClasses").appendChild(row);
                });
            });
        });
    }).catch(e => {
        $("loader").style.display = "none";
        $("analyzeBtn").disabled = false;
        $("predictionText").textContent = "Error: " + e.message;
    });
};
