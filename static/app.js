const state={
    ws:null,
    isConnected:false,
    engineRunning:false,
    enginePaused:false,
    activeModel:'xgboost',
    soundEnabled:true,
    filterMode:'all',
    maxTableRows:80,
    audioCtx:null,
    localIps:new Set(['127.0.0.1','::1']),
    gatewayIps:new Set(['192.168.29.1']),
    totalFlows:0,
    benignFlows:0,
    threatsDetected:0,
    inBytesTotal:0,
    outBytesTotal:0,
    throughputHistory:{
        labels:[],
        inbound:[],
        outbound:[]
    },
    durationHistory:{
        labels:[],
        duration:[]
    },
    protocolCounts:{
        'HTTPS (443)':0,
        'HTTP (80)':0,
        'DNS (53)':0,
        'SSH (22)':0,
        'Other TCP':0,
        'UDP / Other':0
    },
    radarFeatures:[0,0,0,0,0,0,0,0]
};

const DOM={
    engineStatusBadge:document.getElementById('engineStatusBadge'),
    engineStatusText:document.getElementById('engineStatusText'),
    trafficFeedSelector:document.getElementById('trafficFeedSelector'),
    modelSelector:document.getElementById('modelSelector'),
    btnStart:document.getElementById('btnStart'),
    btnPause:document.getElementById('btnPause'),
    btnStop:document.getElementById('btnStop'),
    btnAudioToggle:document.getElementById('btnAudioToggle'),
    audioIcon:document.getElementById('audioIcon'),
    threatAlertBanner:document.getElementById('threatAlertBanner'),
    threatSeverityBadge:document.getElementById('threatSeverityBadge'),
    threatTitleText:document.getElementById('threatTitleText'),
    threatTimeText:document.getElementById('threatTimeText'),
    threatDescText:document.getElementById('threatDescText'),
    threatSrcIp:document.getElementById('threatSrcIp'),
    threatDstPort:document.getElementById('threatDstPort'),
    threatConfidence:document.getElementById('threatConfidence'),
    threatModel:document.getElementById('threatModel'),
    deviceAlertStatus:document.getElementById('deviceAlertStatus'),
    btnDismissAlert:document.getElementById('btnDismissAlert'),
    kpiTotalFlows:document.getElementById('kpiTotalFlows'),
    kpiBenignFlows:document.getElementById('kpiBenignFlows'),
    kpiBenignPct:document.getElementById('kpiBenignPct'),
    kpiThreatsDetected:document.getElementById('kpiThreatsDetected'),
    kpiThreatSubtext:document.getElementById('kpiThreatSubtext'),
    kpiLatency:document.getElementById('kpiLatency'),
    kpiBandwidth:document.getElementById('kpiBandwidth'),
    kpiInRate:document.getElementById('kpiInRate'),
    kpiOutRate:document.getElementById('kpiOutRate'),
    cpuBar:document.getElementById('cpuBar'),
    cpuVal:document.getElementById('cpuVal'),
    memBar:document.getElementById('memBar'),
    memVal:document.getElementById('memVal'),
    hostPktsSent:document.getElementById('hostPktsSent'),
    hostPktsRecv:document.getElementById('hostPktsRecv'),
    flowTableBody:document.getElementById('flowTableBody'),
    btnClearTable:document.getElementById('btnClearTable'),
    notifModal:document.getElementById('notifModal'),
    btnNotifConfig:document.getElementById('btnNotifConfig'),
    btnCloseNotifModal:document.getElementById('btnCloseNotifModal'),
    btnSaveNotifConfig:document.getElementById('btnSaveNotifConfig'),
    btnSendTestNotif:document.getElementById('btnSendTestNotif'),
    testNotifStatus:document.getElementById('testNotifStatus'),
    chkDesktopToast:document.getElementById('chkDesktopToast'),
    chkSoundAlert:document.getElementById('chkSoundAlert'),
    rngCooldown:document.getElementById('rngCooldown'),
    cooldownValLabel:document.getElementById('cooldownValLabel'),
    rngMinConfidence:document.getElementById('rngMinConfidence'),
    confValLabel:document.getElementById('confValLabel'),
    selMinSeverity:document.getElementById('selMinSeverity'),
    chkWebhook:document.getElementById('chkWebhook'),
    txtWebhookUrl:document.getElementById('txtWebhookUrl'),
    metricsModal:document.getElementById('metricsModal'),
    btnModelMetrics:document.getElementById('btnModelMetrics'),
    btnCloseMetricsModal:document.getElementById('btnCloseMetricsModal'),
    btnCloseMetricsModal2:document.getElementById('btnCloseMetricsModal2'),
};

let throughputChart=null;
let durationChart=null;
let protocolChart=null;
let featureRadarChart=null;

function initCharts(){
    const ctxThroughput=document.getElementById('throughputChart').getContext('2d');
    const gradCyan=ctxThroughput.createLinearGradient(0,0,0,200);
    gradCyan.addColorStop(0,'rgba(0,240,255,0.3)');
    gradCyan.addColorStop(1,'rgba(0,240,255,0.0)');
    const gradPurple=ctxThroughput.createLinearGradient(0,0,0,200);
    gradPurple.addColorStop(0,'rgba(168,85,247,0.3)');
    gradPurple.addColorStop(1,'rgba(168,85,247,0.0)');
    throughputChart=new Chart(ctxThroughput,{
        type:'line',
        data:{
            labels:[],
            datasets:[
                {
                    label:'Inbound (Bytes/s)',
                    borderColor:'#00f0ff',
                    backgroundColor:gradCyan,
                    borderWidth:2,
                    fill:true,
                    tension:0.35,
                    pointRadius:0,
                    data:[]
                },
                {
                    label:'Outbound (Bytes/s)',
                    borderColor:'#a855f7',
                    backgroundColor:gradPurple,
                    borderWidth:2,
                    fill:true,
                    tension:0.35,
                    pointRadius:0,
                    data:[]
                }
            ]
        },
        options:{
            responsive:true,
            maintainAspectRatio:false,
            animation:false,
            scales:{
                x:{
                    display:true,
                    grid:{color:'rgba(255,255,255,0.05)'},
                    ticks:{color:'#64748b',font:{size:10,family:'JetBrains Mono'}}
                },
                y:{
                    display:true,
                    beginAtZero:true,
                    grid:{color:'rgba(255,255,255,0.05)'},
                    ticks:{color:'#64748b',font:{size:10,family:'JetBrains Mono'}}
                }
            },
            plugins:{
                legend:{
                    labels:{color:'#94a3b8',font:{size:11,family:'JetBrains Mono'}}
                }
            }
        }
    });

    const ctxDuration=document.getElementById('durationChart').getContext('2d');
    const gradGreen=ctxDuration.createLinearGradient(0,0,0,200);
    gradGreen.addColorStop(0,'rgba(0,255,157,0.3)');
    gradGreen.addColorStop(1,'rgba(0,255,157,0.0)');
    durationChart=new Chart(ctxDuration,{
        type:'line',
        data:{
            labels:[],
            datasets:[{
                label:'Flow Duration (ms)',
                borderColor:'#00ff9d',
                backgroundColor:gradGreen,
                borderWidth:2,
                fill:true,
                tension:0.3,
                pointRadius:1,
                data:[]
            }]
        },
        options:{
            responsive:true,
            maintainAspectRatio:false,
            animation:false,
            scales:{
                x:{display:false},
                y:{
                    beginAtZero:true,
                    grid:{color:'rgba(255,255,255,0.05)'},
                    ticks:{color:'#64748b',font:{size:9,family:'JetBrains Mono'}}
                }
            },
            plugins:{
                legend:{display:false}
            }
        }
    });

    const ctxProtocol=document.getElementById('protocolChart').getContext('2d');
    protocolChart=new Chart(ctxProtocol,{
        type:'doughnut',
        data:{
            labels:Object.keys(state.protocolCounts),
            datasets:[{
                data:[15,10,8,4,12,6],
                backgroundColor:[
                    '#00f0ff',
                    '#00ff9d',
                    '#a855f7',
                    '#ffb800',
                    '#38bdf8',
                    '#64748b'
                ],
                borderColor:'#0b1120',
                borderWidth:3
            }]
        },
        options:{
            responsive:true,
            maintainAspectRatio:false,
            cutout:'70%',
            plugins:{
                legend:{
                    position:'right',
                    labels:{color:'#94a3b8',font:{size:10,family:'JetBrains Mono'},boxWidth:10}
                }
            }
        }
    });

    const ctxRadar=document.getElementById('featureRadarChart').getContext('2d');
    featureRadarChart=new Chart(ctxRadar,{
        type:'radar',
        data:{
            labels:['Shortest Pkt','Longest Pkt','Throughput In','Throughput Out','TCP Win','Flow Duration','TTL Envelope','Packet Rate'],
            datasets:[{
                label:'Normalized Flow Intensity',
                data:[20,60,45,30,70,25,64,40],
                backgroundColor:'rgba(0,240,255,0.2)',
                borderColor:'#00f0ff',
                borderWidth:2,
                pointBackgroundColor:'#00f0ff',
                pointRadius:3
            }]
        },
        options:{
            responsive:true,
            maintainAspectRatio:false,
            animation:false,
            scales:{
                r:{
                    angleLines:{color:'rgba(255,255,255,0.1)'},
                    grid:{color:'rgba(255,255,255,0.08)'},
                    pointLabels:{color:'#94a3b8',font:{size:9,family:'JetBrains Mono'}},
                    ticks:{display:false,min:0,max:100}
                }
            },
            plugins:{
                legend:{display:false}
            }
        }
    });
}

function playThreatSiren(){
    if(!state.soundEnabled)return;
    try{
        if(!state.audioCtx){
            state.audioCtx=new (window.AudioContext||window.webkitAudioContext)();
        }
        const ctx=state.audioCtx;
        if(ctx.state==='suspended'){
            ctx.resume();
        }
        const osc=ctx.createOscillator();
        const gain=ctx.createGain();
        osc.type='sawtooth';
        const now=ctx.currentTime;
        osc.frequency.setValueAtTime(800,now);
        osc.frequency.linearRampToValueAtTime(1200,now+0.15);
        osc.frequency.linearRampToValueAtTime(800,now+0.3);
        osc.frequency.linearRampToValueAtTime(1200,now+0.45);
        osc.frequency.linearRampToValueAtTime(800,now+0.6);
        gain.gain.setValueAtTime(0.2,now);
        gain.gain.exponentialRampToValueAtTime(0.01,now+0.65);
        osc.connect(gain);
        gain.connect(ctx.destination);
        osc.start(now);
        osc.stop(now+0.65);
    }catch(e){
        console.warn('Audio playback error:',e);
    }
}

function triggerBrowserNotification(title,body){
    if('Notification' in window&&Notification.permission==='granted'){
        try{
            new Notification(title,{
                body:body,
                requireInteraction:false
            });
        }catch(e){
            console.warn('Browser notification error:',e);
        }
    }
}

function connectWebSocket(){
    const protocol=window.location.protocol==='https:'?'wss:':'ws:';
    const wsUrl=`${protocol}//${window.location.host}/ws/telemetry`;
    state.ws=new WebSocket(wsUrl);
    state.ws.onopen=()=>{
        state.isConnected=true;
        console.log('Connected to IDS WebSocket telemetry stream.');
    };
    state.ws.onmessage=(event)=>{
        try{
            const data=JSON.parse(event.data);
            handleWebSocketMessage(data);
        }catch(err){
            console.error('Error parsing WebSocket message:',err);
        }
    };
    state.ws.onclose=()=>{
        state.isConnected=false;
        console.warn('WebSocket closed. Reconnecting in 2 seconds...');
        setTimeout(connectWebSocket,2000);
    };
    state.ws.onerror=(err)=>{
        console.error('WebSocket encountered error:',err);
    };
}

function handleWebSocketMessage(msg){
    if(msg.type==='init_state'){
        const engine=msg.dashboard.engine;
        updateEngineState(engine.state);
        state.activeModel=engine.active_model;
        DOM.modelSelector.value=engine.active_model;
        if(msg.dashboard.local_ips){
            msg.dashboard.local_ips.forEach(ip=>state.localIps.add(ip.toLowerCase()));
        }
        if(msg.dashboard.gateway_ips){
            msg.dashboard.gateway_ips.forEach(ip=>state.gatewayIps.add(ip.toLowerCase()));
        }
        if(msg.dashboard.stats){
            updateStatsUI(msg.dashboard.stats);
        }
        if(msg.notification_config){
            DOM.chkDesktopToast.checked=msg.notification_config.desktop_toasts;
            DOM.chkSoundAlert.checked=msg.notification_config.sound_enabled;
            DOM.rngCooldown.value=msg.notification_config.cooldown_seconds;
            DOM.cooldownValLabel.textContent=msg.notification_config.cooldown_seconds;
            DOM.rngMinConfidence.value=Math.round(msg.notification_config.min_confidence*100);
            DOM.confValLabel.textContent=`${Math.round(msg.notification_config.min_confidence*100)}%`;
            DOM.selMinSeverity.value=msg.notification_config.min_severity;
        }
    }else if(msg.type==='telemetry_tick'){
        if(msg.stats){
            updateStatsUI(msg.stats);
        }
        if(msg.host){
            updateHostTelemetryUI(msg.host);
        }
        if(msg.flows&&msg.flows.length>0){
            msg.flows.forEach(flow=>{
                processIncomingFlow(flow);
            });
        }
    }else if(msg.type==='simulated_threat'){
        if(msg.stats){
            updateStatsUI(msg.stats);
        }
        if(msg.flow){
            processIncomingFlow(msg.flow);
            displayThreatAlert(msg.flow);
        }
    }
}

function updateEngineState(engineState){
    DOM.engineStatusBadge.className='engine-badge';
    if(engineState==='running'){
        state.engineRunning=true;
        state.enginePaused=false;
        DOM.engineStatusBadge.classList.add('badge-active');
        DOM.engineStatusText.textContent='ONLINE // SCANNING';
        DOM.btnStart.disabled=true;
        DOM.btnPause.disabled=false;
        DOM.btnStop.disabled=false;
    }else if(engineState==='paused'){
        state.engineRunning=true;
        state.enginePaused=true;
        DOM.engineStatusBadge.classList.add('badge-paused');
        DOM.engineStatusText.textContent='PAUSED';
        DOM.btnStart.disabled=false;
        DOM.btnPause.disabled=true;
        DOM.btnStop.disabled=false;
    }else{
        state.engineRunning=false;
        state.enginePaused=false;
        DOM.engineStatusText.textContent='SYSTEM IDLE';
        DOM.btnStart.disabled=false;
        DOM.btnPause.disabled=true;
        DOM.btnStop.disabled=true;
    }
}

function updateStatsUI(stats){
    state.totalFlows=stats.total_flows_inspected;
    state.benignFlows=stats.benign_flows_count;
    state.threatsDetected=stats.threats_detected_count;
    DOM.kpiTotalFlows.textContent=state.totalFlows.toLocaleString();
    DOM.kpiBenignFlows.textContent=state.benignFlows.toLocaleString();
    DOM.kpiThreatsDetected.textContent=state.threatsDetected.toLocaleString();
    const pct=state.totalFlows>0?((state.benignFlows/state.totalFlows)*100).toFixed(1):'100.0';
    DOM.kpiBenignPct.textContent=`${pct}%`;
    DOM.kpiThreatSubtext.textContent=`${state.threatsDetected} threats intercepted & logged`;
    DOM.kpiLatency.textContent=stats.last_inference_latency_ms.toFixed(2);
}

function updateHostTelemetryUI(host){
    DOM.cpuBar.style.width=`${Math.min(100,host.cpu_percent)}%`;
    DOM.cpuVal.textContent=`${Math.round(host.cpu_percent)}%`;
    DOM.memBar.style.width=`${Math.min(100,host.memory_percent)}%`;
    DOM.memVal.textContent=`${Math.round(host.memory_percent)}%`;
    DOM.hostPktsSent.textContent=host.packets_sent.toLocaleString();
    DOM.hostPktsRecv.textContent=host.packets_recv.toLocaleString();
}

function processIncomingFlow(flow){
    const timeLabel=flow.time_formatted||new Date().toLocaleTimeString();
    const inRate=flow.in_bytes;
    const outRate=flow.out_bytes;
    const totalKBps=((inRate+outRate)/1024).toFixed(1);
    DOM.kpiBandwidth.textContent=totalKBps;
    DOM.kpiInRate.textContent=(inRate/1024).toFixed(1);
    DOM.kpiOutRate.textContent=(outRate/1024).toFixed(1);
    if(throughputChart){
        throughputChart.data.labels.push(timeLabel);
        throughputChart.data.datasets[0].data.push(inRate);
        throughputChart.data.datasets[1].data.push(outRate);
        if(throughputChart.data.labels.length>25){
            throughputChart.data.labels.shift();
            throughputChart.data.datasets[0].data.shift();
            throughputChart.data.datasets[1].data.shift();
        }
        throughputChart.update('none');
    }
    if(durationChart){
        durationChart.data.labels.push(timeLabel);
        durationChart.data.datasets[0].data.push(flow.flow_duration_ms||1.0);
        if(durationChart.data.labels.length>25){
            durationChart.data.labels.shift();
            durationChart.data.datasets[0].data.shift();
        }
        durationChart.update('none');
    }
    const dstPort=flow.dst_port;
    if(dstPort===443)state.protocolCounts['HTTPS (443)']++;
    else if(dstPort===80)state.protocolCounts['HTTP (80)']++;
    else if(dstPort===53)state.protocolCounts['DNS (53)']++;
    else if(dstPort===22)state.protocolCounts['SSH (22)']++;
    else if(flow.protocol==='TCP')state.protocolCounts['Other TCP']++;
    else state.protocolCounts['UDP / Other']++;
    if(protocolChart&&state.totalFlows%3===0){
        protocolChart.data.datasets[0].data=Object.values(state.protocolCounts);
        protocolChart.update('none');
    }
    if(featureRadarChart&&flow.feature_snapshot){
        const snap=flow.feature_snapshot;
        const normalized=[
            Math.min(100,(snap.shortest_pkt/64)*50),
            Math.min(100,(snap.longest_pkt/1500)*100),
            Math.min(100,(snap.throughput_in/100000)*100),
            Math.min(100,(snap.throughput_out/100000)*100),
            Math.min(100,(snap.tcp_win_in/65535)*100),
            Math.min(100,(flow.flow_duration_ms/50)*50),
            flow.is_threat?95:60,
            Math.min(100,flow.in_bytes/50)
        ];
        featureRadarChart.data.datasets[0].data=normalized;
        featureRadarChart.update('none');
    }
    appendFlowToTable(flow);
    if(flow.is_threat){
        displayThreatAlert(flow);
    }
}

function formatIpCell(ip,port,isLocal,isGateway,role){
    let ipClass=(isLocal||isGateway)?'ip-local':'ip-remote';
    let badgeHtml='';
    if(role==='threat_remote_attacker'){
        ipClass='ip-attacker';
        badgeHtml=`<span class="ip-badge badge-attacker">🚨 ATTACKER</span>`;
    }else if(role==='threat_local_victim'){
        ipClass='ip-local';
        badgeHtml=`<span class="ip-badge badge-victim">🎯 VICTIM (THIS PC)</span>`;
    }else if(role==='threat_local_origin'){
        ipClass='ip-local';
        badgeHtml=`<span class="ip-badge badge-thispc">💻 THIS PC</span>`;
    }else if(role==='threat_remote_target'){
        ipClass='ip-remote';
        badgeHtml=`<span class="ip-badge badge-remote">🌐 REMOTE</span>`;
    }else if(isGateway){
        badgeHtml=`<span class="ip-badge badge-gateway">📡 GATEWAY</span>`;
    }else if(isLocal){
        badgeHtml=`<span class="ip-badge badge-thispc">💻 THIS PC</span>`;
    }else{
        badgeHtml=`<span class="ip-badge badge-remote">🌐 REMOTE</span>`;
    }
    return `<div class="ip-cell"><span class="${ipClass}"><strong>${ip}</strong>:${port}</span> ${badgeHtml}</div>`;
}

function appendFlowToTable(flow){
    const tbody=DOM.flowTableBody;
    const emptyRow=tbody.querySelector('.empty-row');
    if(emptyRow){
        emptyRow.remove();
    }
    const isHidden=(state.filterMode==='benign'&&flow.is_threat)||
                     (state.filterMode==='threat'&&!flow.is_threat);
    const row=document.createElement('tr');
    if(flow.is_threat){
        row.classList.add('threat-row');
    }
    if(isHidden){
        row.style.display='none';
    }
    const cleanSrc=flow.src_ip.toLowerCase().split('%')[0];
    const cleanDst=flow.dst_ip.toLowerCase().split('%')[0];
    const srcIsLocal=flow.src_is_local||state.localIps.has(cleanSrc);
    const dstIsLocal=flow.dst_is_local||state.localIps.has(cleanDst);
    const srcIsGateway=flow.src_is_gateway||state.gatewayIps.has(cleanSrc);
    const dstIsGateway=flow.dst_is_gateway||state.gatewayIps.has(cleanDst);
    let srcRole=srcIsGateway?'normal_gateway':(srcIsLocal?'normal_local':'normal_remote');
    let dstRole=dstIsGateway?'normal_gateway':(dstIsLocal?'normal_local':'normal_remote');
    if(flow.is_threat){
        if(!srcIsLocal&&dstIsLocal&&!srcIsGateway){
            srcRole='threat_remote_attacker';
            dstRole='threat_local_victim';
        }else if(srcIsLocal&&!dstIsLocal){
            srcRole='threat_local_origin';
            dstRole='threat_remote_target';
        }else{
            srcRole=srcIsLocal?'threat_local_victim':'threat_remote_attacker';
            dstRole=dstIsLocal?'threat_local_victim':'threat_remote_target';
        }
    }
    const srcHtml=formatIpCell(flow.src_ip,flow.src_port,srcIsLocal,srcIsGateway,srcRole);
    const dstHtml=formatIpCell(flow.dst_ip,flow.dst_port,dstIsLocal,dstIsGateway,dstRole);
    const tagClass=flow.is_threat?'tag-threat':'tag-benign';
    const labelText=flow.is_threat?`🚨 ${flow.label.toUpperCase()}`:'BENIGN';
    const confText=`${Math.round(flow.confidence*100)}%`;
    row.innerHTML=`
        <td>${flow.time_formatted}</td>
        <td>${srcHtml}</td>
        <td>${dstHtml}</td>
        <td><span class="f-chip">${flow.protocol}</span></td>
        <td>${flow.in_bytes.toLocaleString()} B</td>
        <td>${flow.out_bytes.toLocaleString()} B</td>
        <td>${flow.flow_duration_ms} ms</td>
        <td><span class="${tagClass}">${labelText}</span></td>
        <td>${confText}</td>
        <td>${flow.model_used.toUpperCase()}</td>
    `;
    tbody.insertBefore(row,tbody.firstChild);
    while(tbody.children.length>state.maxTableRows){
        tbody.removeChild(tbody.lastChild);
    }
}

function displayThreatAlert(flow){
    const cleanSrc=flow.src_ip.toLowerCase().split('%')[0];
    const cleanDst=flow.dst_ip.toLowerCase().split('%')[0];
    const srcIsLocal=flow.src_is_local||state.localIps.has(cleanSrc);
    const dstIsLocal=flow.dst_is_local||state.localIps.has(cleanDst);
    const srcTag=srcIsLocal?'<span class="ip-badge badge-thispc">THIS PC (CLIENT)</span>':'<span class="ip-badge badge-attacker">REMOTE ATTACKER</span>';
    const dstTag=dstIsLocal?'<span class="ip-badge badge-victim">THIS PC (TARGET)</span>':'<span class="ip-badge badge-remote">REMOTE SERVER</span>';
    DOM.threatAlertBanner.classList.remove('hidden');
    DOM.threatSeverityBadge.textContent=`${flow.severity} THREAT`;
    DOM.threatTitleText.textContent=`${flow.label} Attack Detected!`;
    DOM.threatTimeText.textContent=flow.time_formatted;
    if(DOM.threatDescText){
        DOM.threatDescText.innerHTML=`
            Origin: <strong class="${srcIsLocal?'ip-local':'ip-attacker'}">${flow.src_ip}:${flow.src_port}</strong> ${srcTag} ➔ Destination: <strong class="${dstIsLocal?'ip-local':'ip-remote'}">${flow.dst_ip}:${flow.dst_port}</strong> ${dstTag} | Confidence: <strong>${Math.round(flow.confidence*100)}%</strong> | Model: <span>${flow.model_used.toUpperCase()}</span>
        `;
    }
    DOM.engineStatusBadge.className='engine-badge badge-threat';
    DOM.engineStatusText.textContent='🚨 THREAT DETECTED';
    playThreatSiren();
    triggerBrowserNotification(
        `🛡️ Windows Defender: ${flow.label} Detected!`,
        `[${flow.severity}] Origin: ${flow.src_ip} -> Destination: ${flow.dst_ip}. Confidence: ${Math.round(flow.confidence*100)}%`
    );
}

function setupEventListeners(){
    document.addEventListener('click',()=>{
        if('Notification' in window&&Notification.permission==='default'){
            Notification.requestPermission();
        }
    },{once:true});
    DOM.btnStart.addEventListener('click',()=>{
        fetch('/api/engine/start',{method:'POST'})
            .then(res=>res.json())
            .then(()=>updateEngineState('running'))
            .catch(console.error);
    });
    DOM.btnPause.addEventListener('click',()=>{
        fetch('/api/engine/pause',{method:'POST'})
            .then(res=>res.json())
            .then(()=>updateEngineState('paused'))
            .catch(console.error);
    });
    DOM.btnStop.addEventListener('click',()=>{
        fetch('/api/engine/stop',{method:'POST'})
            .then(res=>res.json())
            .then(()=>updateEngineState('stopped'))
            .catch(console.error);
    });
    if(DOM.trafficFeedSelector){
        DOM.trafficFeedSelector.addEventListener('change',(e)=>{
            const mode=e.target.value;
            fetch('/api/engine/traffic_mode',{
                method:'POST',
                headers:{'Content-Type':'application/json'},
                body:JSON.stringify({mode:mode})
            })
            .then(res=>res.json())
            .then(data=>{
                console.log('Traffic source changed to:',data.traffic_mode);
            })
            .catch(console.error);
        });
    }
    DOM.modelSelector.addEventListener('change',(e)=>{
        const model=e.target.value;
        fetch('/api/engine/model',{
            method:'POST',
            headers:{'Content-Type':'application/json'},
            body:JSON.stringify({model:model})
        })
        .then(res=>res.json())
        .then(data=>{
            state.activeModel=data.active_model;
            console.log('Model switched to:',state.activeModel);
        })
        .catch(console.error);
    });
    DOM.btnAudioToggle.addEventListener('click',()=>{
        state.soundEnabled=!state.soundEnabled;
        DOM.audioIcon.textContent=state.soundEnabled?'🔊':'🔇';
    });
    DOM.btnDismissAlert.addEventListener('click',()=>{
        DOM.threatAlertBanner.classList.add('hidden');
        if(state.engineRunning&&!state.enginePaused){
            DOM.engineStatusBadge.className='engine-badge badge-active';
            DOM.engineStatusText.textContent='ONLINE // SCANNING';
        }
    });
    document.querySelectorAll('.btn-sim').forEach(btn=>{
        btn.addEventListener('click',()=>{
            const attackType=btn.dataset.attack;
            fetch('/api/simulate/attack',{
                method:'POST',
                headers:{'Content-Type':'application/json'},
                body:JSON.stringify({attack_type:attackType})
            })
            .then(res=>res.json())
            .then(data=>{
                console.log('Simulated attack dispatched:',data);
            })
            .catch(console.error);
        });
    });
    document.querySelectorAll('.filter-btn').forEach(btn=>{
        btn.addEventListener('click',()=>{
            document.querySelectorAll('.filter-btn').forEach(b=>b.classList.remove('active'));
            btn.classList.add('active');
            state.filterMode=btn.dataset.filter;
            applyTableFilter();
        });
    });
    DOM.btnClearTable.addEventListener('click',()=>{
        DOM.flowTableBody.innerHTML='<tr class="empty-row"><td colspan="10">Table cleared. Incoming flows will appear here.</td></tr>';
    });
    DOM.btnNotifConfig.addEventListener('click',()=>{
        DOM.notifModal.classList.remove('hidden');
    });
    DOM.btnCloseNotifModal.addEventListener('click',()=>{
        DOM.notifModal.classList.add('hidden');
    });
    DOM.rngCooldown.addEventListener('input',(e)=>{
        DOM.cooldownValLabel.textContent=e.target.value;
    });
    DOM.rngMinConfidence.addEventListener('input',(e)=>{
        DOM.confValLabel.textContent=`${e.target.value}%`;
    });
    DOM.btnSendTestNotif.addEventListener('click',()=>{
        DOM.testNotifStatus.textContent='Sending test Windows Defender alert...';
        fetch('/api/notifications/test',{method:'POST'})
            .then(res=>res.json())
            .then(data=>{
                DOM.testNotifStatus.textContent='✅ '+data.message;
                playThreatSiren();
                triggerBrowserNotification('🛡️ Windows Defender Test Alert','Test notification dispatched successfully!');
            })
            .catch(err=>{
                DOM.testNotifStatus.textContent='❌ Error sending test notification';
            });
    });
    DOM.btnSaveNotifConfig.addEventListener('click',()=>{
        const config={
            desktop_toasts:DOM.chkDesktopToast.checked,
            sound_enabled:DOM.chkSoundAlert.checked,
            cooldown_seconds:parseFloat(DOM.rngCooldown.value),
            min_confidence:parseFloat(DOM.rngMinConfidence.value)/100.0,
            min_severity:DOM.selMinSeverity.value,
            webhook_enabled:DOM.chkWebhook.checked,
            webhook_url:DOM.txtWebhookUrl.value
        };
        fetch('/api/notifications/config',{
            method:'POST',
            headers:{'Content-Type':'application/json'},
            body:JSON.stringify(config)
        })
        .then(res=>res.json())
        .then(()=>{
            DOM.notifModal.classList.add('hidden');
        })
        .catch(console.error);
    });
    DOM.btnModelMetrics.addEventListener('click',()=>{
        fetch('/api/model/metrics')
            .then(res=>res.json())
            .then(data=>{
                if(data.selected_features){
                    const cont=document.getElementById('featureChipsContainer');
                    if(cont){
                        cont.innerHTML=data.selected_features.map(f=>`<span class="f-chip">${f}</span>`).join('');
                    }
                }
            })
            .catch(console.error);
        DOM.metricsModal.classList.remove('hidden');
    });
    DOM.btnCloseMetricsModal.addEventListener('click',()=>{
        DOM.metricsModal.classList.add('hidden');
    });
    DOM.btnCloseMetricsModal2.addEventListener('click',()=>{
        DOM.metricsModal.classList.add('hidden');
    });
}

function applyTableFilter(){
    const rows=DOM.flowTableBody.querySelectorAll('tr:not(.empty-row)');
    rows.forEach(row=>{
        const isThreat=row.classList.contains('threat-row');
        if(state.filterMode==='all'){
            row.style.display='';
        }else if(state.filterMode==='benign'){
            row.style.display=isThreat?'none':'';
        }else if(state.filterMode==='threat'){
            row.style.display=isThreat?'':'none';
        }
    });
}

document.addEventListener('DOMContentLoaded',()=>{
    initCharts();
    setupEventListeners();
    connectWebSocket();
});
