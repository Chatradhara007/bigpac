const appButtons = document.querySelectorAll('.app-btn');
const analyzeBtn = document.getElementById('analyzeBtn');
const packetStream = document.getElementById('packetStream');
const predictionText = document.getElementById('predictionText');
const confContainer = document.getElementById('confContainer');
const confidenceBar = document.getElementById('confidenceBar');
const confidenceValue = document.getElementById('confidenceValue');
const loader = document.getElementById('loader');
const topClasses = document.getElementById('topClasses');

let selectedApp = null;
const MAX_PACKETS = 15; // Model N=15

// Simulated profiles to make the fake packets look somewhat realistic before sending
const profiles = {
    'youtube': { sizeMean: 1200, sizeVar: 200, iatMean: 5 },
    'discord': { sizeMean: 300, sizeVar: 100, iatMean: 50 },
    'spotify': { sizeMean: 1000, sizeVar: 300, iatMean: 10 },
    'whatsapp': { sizeMean: 150, sizeVar: 50, iatMean: 100 },
    'facebook-web': { sizeMean: 700, sizeVar: 400, iatMean: 20 }
};

appButtons.forEach(btn => {
    btn.addEventListener('click', () => {
        appButtons.forEach(b => b.classList.remove('selected'));
        btn.classList.add('selected');
        selectedApp = btn.getAttribute('data-app');
        analyzeBtn.disabled = false;
    });
});

function generateSimulatedFeatures(app) {
    const profile = profiles[app] || profiles['youtube'];
    const features = [];
    
    // We need 45 features (15 packets * 3 properties)
    for (let i = 0; i < MAX_PACKETS; i++) {
        // Size
        let size = Math.floor(profile.sizeMean + (Math.random() * profile.sizeVar * 2 - profile.sizeVar));
        size = Math.max(64, Math.min(1500, size));
        
        // Direction (mostly download)
        let dir = Math.random() > 0.2 ? -1 : 1; 
        
        // IAT
        let iat = Math.floor(Math.random() * profile.iatMean * 2);
        
        features.push(size, dir, iat);
    }
    return features;
}

function animatePackets(features, callback) {
    packetStream.innerHTML = ''; // Clear stream
    let i = 0;
    
    const interval = setInterval(() => {
        if (i >= MAX_PACKETS) {
            clearInterval(interval);
            setTimeout(callback, 500); // slight pause before analysis
            return;
        }
        
        // Extract size from the flat array (idx = i * 3)
        const size = features[i * 3]; 
        const dir = features[i * 3 + 1];
        
        const packet = document.createElement('div');
        packet.classList.add('packet');
        
        // Height based on packet size
        const height = Math.max(10, (size / 1500) * 100);
        packet.style.height = `${height}%`;
        
        // Color based on direction
        packet.style.backgroundColor = dir === -1 ? 'var(--primary)' : 'var(--accent-1)';
        
        packetStream.appendChild(packet);
        i++;
    }, 100); // 100ms per packet visual
}

analyzeBtn.addEventListener('click', () => {
    if (!selectedApp) return;
    
    // Reset UI
    analyzeBtn.disabled = true;
    predictionText.innerText = '';
    confContainer.style.display = 'none';
    confidenceValue.innerText = '';
    topClasses.innerHTML = '';
    loader.style.display = 'block';
    
    // Fetch a REAL sample from the backend
    fetch(`/get_sample/${selectedApp}`)
        .then(response => response.json())
        .then(data => {
            if (data.error) {
                loader.style.display = 'none';
                analyzeBtn.disabled = false;
                predictionText.innerText = "Error loading sample";
                return;
            }
            
            const features = data.features;
            
            // Step 1: Animate the real packets arriving
            animatePackets(features, () => {
                // Step 2: Send to backend for prediction
                fetch('/predict', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ features: features })
                })
                .then(response => response.json())
                .then(data => {
                    loader.style.display = 'none';
                    analyzeBtn.disabled = false;
                    
                    if (data.error) {
                        predictionText.innerText = "Error";
                        return;
                    }
                    
                    // Display Results
                    predictionText.innerText = data.prediction;
                    
                    const confPercent = (data.confidence * 100).toFixed(1);
                    confContainer.style.display = 'block';
                    
                    // Use setTimeout to allow CSS transition to play
                    setTimeout(() => {
                        confidenceBar.style.width = `${confPercent}%`;
                    }, 50);
                    
                    confidenceValue.innerText = `${confPercent}% Confidence`;
                    
                    // Display top 3
                    data.top_3.forEach(item => {
                        const row = document.createElement('div');
                        row.classList.add('class-row');
                        row.innerHTML = `
                            <span>${item.class}</span>
                            <span>${(item.prob * 100).toFixed(1)}%</span>
                        `;
                        topClasses.appendChild(row);
                    });
                    
                })
                .catch(err => {
                    loader.style.display = 'none';
                    analyzeBtn.disabled = false;
                    predictionText.innerText = "Network Error";
                    console.error(err);
                });
            });
        })
        .catch(err => {
            loader.style.display = 'none';
            analyzeBtn.disabled = false;
            predictionText.innerText = "Network Error";
            console.error(err);
        });
});
