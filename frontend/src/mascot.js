export function learningSpeech(snapshot){
  if(!snapshot||typeof snapshot.learning_message!=='string'||!snapshot.learning_seq)return null;
  const kind=['memory','observed','saved','action'].includes(snapshot.learning_kind)?snapshot.learning_kind:'action';
  return {id:String(snapshot.learning_seq),text:snapshot.learning_message.slice(0,200),kind};
}

const STATES = {
  idle: { label: 'Esperando', row: 0 },
  working: { label: 'Lendo', row: 1 },
  tool: { label: 'Trabalhando', row: 2 },
  done: { label: 'Comemorando', row: 3 },
  error: { label: 'Aguardando você', row: 0 },
};

// Pre-rendered frames preserve the reference's appearance without a WebGL renderer.
export function createMascot(container, getMood) {
  const motion = matchMedia('(prefers-reduced-motion: reduce)');
  let paused = false, inView = true, atlasReady = false, preview = null;
  let previewUntil = 0, lastMood = '', nextPreview = 1;
  const order = ['idle', 'working', 'tool', 'done'];
  const button = document.createElement('button');
  button.type = 'button';
  button.className = 'mascot-character';
  button.setAttribute('aria-label', 'Mimo animado. Toque para ver outra animação.');
  const still = document.createElement('img');
  still.className = 'mascot-still';
  still.src = 'assets/cyber-mimo.png';
  still.alt = 'Mimo: pequeno zumbi verde com cabelo roxo, olhos rosa e fones com circuitos neon.';
  still.draggable = false;
  const sprite = document.createElement('span');
  sprite.className = 'mascot-sprite';
  sprite.setAttribute('aria-hidden', 'true');
  button.append(still, sprite);
  const shadow = document.createElement('span');
  shadow.className = 'mascot-image-shadow';
  shadow.setAttribute('aria-hidden', 'true');
  const caption = document.createElement('span');
  caption.className = 'mascot-animation-caption';
  container.append(shadow, button, caption);
  container.classList.add('image-mascot', 'ready');
  container.dataset.asset = 'animated-image';
  const hero=container.closest('.mascot-hero');
  const speech=document.createElement('div');speech.className='mascot-speech';speech.hidden=true;
  speech.setAttribute('role','status');speech.setAttribute('aria-live','polite');speech.setAttribute('aria-atomic','true');
  const speechLabel=document.createElement('strong'),speechText=document.createElement('span');speech.append(speechLabel,speechText);hero.append(speech);
  const speechLabels={memory:'EU LEMBRO',observed:'ACABEI DE OBSERVAR',saved:'GUARDEI NA MEMÓRIA',action:'ESTOU CONFERINDO',demo:'DEMONSTRAÇÃO'};
  let speechQueue=[],lastSpeechId='',lastSpeechText='',speechUntil=0;
  function showSpeech(item){speechLabel.textContent=speechLabels[item.kind]||speechLabels.action;speechText.textContent=item.text;speech.hidden=false;hero.classList.add('has-speech');speech.dataset.kind=item.kind;speech.classList.remove('speech-enter');void speech.offsetWidth;speech.classList.add('speech-enter');speechUntil=Date.now()+7000;lastSpeechText=item.text;}
  function say(text,kind='action'){
    if(!text||text===lastSpeechText||speechQueue.some(item=>item.text===text))return;
    const item={text:String(text).slice(0,200),kind};
    if(kind==='saved'){speechQueue=[];showSpeech(item);return;}
    if(speech.hidden||Date.now()>=speechUntil)showSpeech(item);
    else{speechQueue.push(item);if(speechQueue.length>3)speechQueue.shift();}
  }
  function learn(snapshot){const item=learningSpeech(snapshot);if(!item||item.id===lastSpeechId)return;lastSpeechId=item.id;say(item.text,item.kind);}
  function clearSpeech(){speechQueue=[];lastSpeechId='';lastSpeechText='';speechUntil=0;speech.hidden=true;hero.classList.remove('has-speech');}


  function update() {
    if(!document.hidden&&inView&&Date.now()>=speechUntil&&speechQueue.length)showSpeech(speechQueue.shift());
    if (Date.now() >= previewUntil) preview = null;
    const mood = preview || getMood() || 'idle';
    const info = STATES[mood] || STATES.idle;
    const stopped = paused || motion.matches || document.hidden || !inView;
    container.classList.toggle('sprite-paused', stopped);
    const displayKey = mood + (preview ? '-preview' : '');
    if (displayKey !== lastMood) {
      lastMood = displayKey;
      container.dataset.mood = mood;
      sprite.style.setProperty('--sprite-row', String(info.row));
      caption.textContent = preview ? info.label + ' · prévia da animação' : info.label;
    }
    button.classList.toggle('use-sprite', atlasReady && mood !== 'idle' && mood !== 'error');
  }
  // One illustrated asset, animated locally; no obsolete character atlas.
  atlasReady = false;
  function react() { preview = 'done'; previewUntil = Date.now() + 3200; lastMood = ''; update(); }
  button.addEventListener('click', () => {
    preview = order[nextPreview++ % order.length];
    previewUntil = Date.now() + 5000;
    lastMood = '';
    update();
  });
  const observer = new IntersectionObserver(entries => { inView = entries[0].isIntersecting; update(); });
  observer.observe(container);
  document.addEventListener('visibilitychange', update);
  motion.addEventListener('change', update);
  const timer = setInterval(update, 250);
  update();
  return {
    react, say, learn, clearSpeech,
    setPaused(value) { paused = value; update(); },
    dispose() {
      clearInterval(timer); observer.disconnect();
      document.removeEventListener('visibilitychange', update);
      motion.removeEventListener('change', update);
      button.remove(); shadow.remove(); caption.remove(); speech.remove();
    },
  };
}
