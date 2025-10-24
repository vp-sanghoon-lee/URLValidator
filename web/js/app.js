(() => {
  const $ = (id) => document.getElementById(id);
  const $url = $("url");
  const $btn = $("btn");
  const $wait = $("wait");
  const $showRaw = $("showRaw");
  const $status = $("status");
  const $result = $("result");
  const $verdict = $("verdict");
  const $method = $("method");
  const $urlEcho = $("urlEcho");
  const $stats = $("stats");
  const $rawBox = $("rawBox");
  const $raw = $("raw");

  const BASE_API = window.APP_CONFIG?.BASE_API || "";

  function setBadge(v){
    $verdict.className = "badge " + (v==="악성"?"bad":v==="주의"?"warn":v==="정상"?"ok":"unk");
    $verdict.textContent = v;
  }

  function setBusy(b){
    $btn.disabled = b;
    $status.textContent = b ? "분석 중…" : "대기 중…";
  }

  async function scan(){
    const url = ($url.value || "").trim();
    if(!url){ alert("URL을 입력하세요."); $url.focus(); return; }

    setBusy(true);
    $result.style.display = "none";
    $rawBox.style.display = "none";

    try{
      const res = await fetch(`${BASE_API}/urlvalidator/scan`, {
        method: "POST",
        headers: {"Content-Type":"application/json"},
        body: JSON.stringify({ url, wait: $wait.checked })
      });
      const data = await res.json();
      if(!res.ok) throw new Error(data?.detail || `요청 실패 (${res.status})`);

      $result.style.display = "block";
      setBadge(data.result || "unknown");
      $method.textContent = data.source || "-";
      $urlEcho.textContent = data.url || url;

      const s = data.details.data.attributes.stats || {};
      $stats.textContent = `malicious=${s.malicious||0}, suspicious=${s.suspicious||0}, harmless=${s.harmless||0}, undetected=${s.undetected||0}, timeout=${s.timeout||0}`;

      if ($showRaw.checked) {
        $rawBox.style.display = "block";
        $raw.textContent = JSON.stringify(data, null, 2);
      }
      $status.textContent = "완료";
    }catch(err){
      $status.textContent = "오류: " + (err?.message || err);
      $result.style.display = "none";
    }finally{
      setBusy(false);
    }
  }

  $btn.addEventListener("click", scan);
  $url.addEventListener("keydown", (e)=>{ if(e.key==="Enter"){ scan(); }});
  $showRaw.addEventListener("change", ()=>{
    $rawBox.style.display = $showRaw.checked ? "block" : "none";
  });
})();
