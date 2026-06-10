const state = {
  participantName: 'Participant',
  currentStep: 0,
  completed: false
};

const welcomeScreen = document.querySelector('#welcome-screen');
const platform = document.querySelector('#platform');
const visitorName = document.querySelector('#visitor-name');
const enterPlatform = document.querySelector('#enter-platform');
const navLinks = document.querySelectorAll('[data-section]');
const sections = document.querySelectorAll('.dashboard-section');
const pageTitle = document.querySelector('#page-title');
const startTour = document.querySelector('#start-tour');
const tourOverlay = document.querySelector('#tour-overlay');
const tourCard = document.querySelector('#tour-card');
const tourProgress = document.querySelector('#tour-progress');
const tourTitle = document.querySelector('#tour-title');
const tourText = document.querySelector('#tour-text');
const tourSkip = document.querySelector('#tour-skip');
const tourPrev = document.querySelector('#tour-prev');
const tourNext = document.querySelector('#tour-next');
const openCertificate = document.querySelector('#open-certificate');
const completeTour = document.querySelector('#complete-tour');
const certificateModal = document.querySelector('#certificate-modal');
const closeCertificate = document.querySelector('#close-certificate');
const certificateName = document.querySelector('#certificate-name');
const downloadCertificate = document.querySelector('#download-certificate');

const sectionTitles = {
  overview: 'Active Directory Posture Dashboard',
  privileged: 'Privileged Group Exposure',
  delegation: 'Kerberos Delegation Risk',
  acl: 'ACL Posture Review',
  kerberos: 'Kerberos and Authentication Hygiene',
  remediation: 'Remediation Planning',
  reports: 'Executive Reporting and Exports'
};

const tourSteps = [
  {
    selector: '[data-tour="brand"]',
    section: 'overview',
    title: 'Product identity',
    text: 'This guided experience presents AD Posture as a professional security assessment toolkit for local Active Directory evidence, posture review, and remediation planning.'
  },
  {
    selector: '[data-tour="metrics"]',
    section: 'overview',
    title: 'Risk summary',
    text: 'The top metrics summarize critical findings, privileged objects, remediation impact, and whether an evidence bundle is ready for review.'
  },
  {
    selector: '[data-tour="score"]',
    section: 'overview',
    title: 'Cumulative risk scoring',
    text: 'AD Posture groups evidence by security domain so an analyst can prioritize where the largest identity exposure exists.'
  },
  {
    selector: '[data-tour="action-plan"]',
    section: 'overview',
    title: 'Prioritized action plan',
    text: 'The action plan translates findings into concrete operational work: remove standing access, review delegation, expire exceptions, and correct drift.'
  },
  {
    selector: '[data-tour="privileged-table"]',
    section: 'privileged',
    title: 'Privileged group chains',
    text: 'This view shows sensitive groups, Tier classification, member count, nested paths, business risk, and recommended action.'
  },
  {
    selector: '[data-tour="reports"]',
    section: 'reports',
    title: 'Executive-ready reporting',
    text: 'The final output is designed for leadership, audit, security engineering, and operations teams that need evidence and a remediation story.'
  }
];

function enterTour() {
  const typedName = visitorName.value.trim();
  state.participantName = typedName || 'Participant';
  certificateName.textContent = state.participantName;
  welcomeScreen.classList.add('hidden');
  platform.classList.remove('hidden');
}

function showSection(sectionId) {
  navLinks.forEach(link => link.classList.toggle('active', link.dataset.section === sectionId));
  sections.forEach(section => section.classList.toggle('active-section', section.id === sectionId));
  pageTitle.textContent = sectionTitles[sectionId] || 'AD Posture Dashboard';
}

function clearHighlight() {
  document.querySelectorAll('.tour-highlight').forEach(element => element.classList.remove('tour-highlight'));
}

function showTourStep(index) {
  state.currentStep = index;
  const step = tourSteps[index];
  showSection(step.section);
  clearHighlight();

  const target = document.querySelector(step.selector);
  if (target) {
    target.classList.add('tour-highlight');
    target.scrollIntoView({ behavior: 'smooth', block: 'center' });
  }

  tourOverlay.classList.remove('hidden');
  tourCard.classList.remove('hidden');
  tourCard.setAttribute('aria-hidden', 'false');
  tourProgress.textContent = `Step ${index + 1} of ${tourSteps.length}`;
  tourTitle.textContent = step.title;
  tourText.textContent = step.text;
  tourPrev.disabled = index === 0;
  tourNext.textContent = index === tourSteps.length - 1 ? 'Finish' : 'Next';
}

function finishTour() {
  state.completed = true;
  clearHighlight();
  tourOverlay.classList.add('hidden');
  tourCard.classList.add('hidden');
  tourCard.setAttribute('aria-hidden', 'true');
  showSection('reports');
  showCertificate();
}

function showCertificate() {
  certificateName.textContent = state.participantName;
  certificateModal.classList.remove('hidden');
}

function hideCertificate() {
  certificateModal.classList.add('hidden');
}

function downloadCertificatePng() {
  const canvas = document.createElement('canvas');
  const width = 1400;
  const height = 900;
  canvas.width = width;
  canvas.height = height;
  const ctx = canvas.getContext('2d');

  const gradient = ctx.createLinearGradient(0, 0, width, height);
  gradient.addColorStop(0, '#07111f');
  gradient.addColorStop(0.55, '#0d1b2f');
  gradient.addColorStop(1, '#10233d');
  ctx.fillStyle = gradient;
  ctx.fillRect(0, 0, width, height);

  ctx.strokeStyle = '#38bdf8';
  ctx.lineWidth = 8;
  ctx.strokeRect(70, 70, width - 140, height - 140);
  ctx.strokeStyle = 'rgba(148, 163, 184, 0.35)';
  ctx.lineWidth = 2;
  ctx.strokeRect(100, 100, width - 200, height - 200);

  ctx.fillStyle = '#38bdf8';
  ctx.font = '700 34px Inter, Arial, sans-serif';
  ctx.textAlign = 'center';
  ctx.fillText('CERTIFICATE OF COMPLETION', width / 2, 210);

  ctx.fillStyle = '#e6edf7';
  ctx.font = '800 78px Inter, Arial, sans-serif';
  wrapCanvasText(ctx, state.participantName, width / 2, 355, 1100, 86);

  ctx.fillStyle = '#8fa4bf';
  ctx.font = '400 30px Inter, Arial, sans-serif';
  wrapCanvasText(ctx, 'has completed the AD Posture Guided Tour covering privileged access, Tier 0 exposure, delegation, ACL posture, Kerberos hygiene, remediation planning, and executive reporting.', width / 2, 500, 1040, 46);

  ctx.fillStyle = '#e6edf7';
  ctx.font = '700 30px Inter, Arial, sans-serif';
  ctx.fillText('AD Posture Interactive Lab', width / 2, 690);

  ctx.fillStyle = '#8fa4bf';
  ctx.font = '400 24px Inter, Arial, sans-serif';
  ctx.fillText(new Date().toLocaleDateString(undefined, { year: 'numeric', month: 'long', day: 'numeric' }), width / 2, 750);

  const link = document.createElement('a');
  link.download = `ad-posture-certificate-${state.participantName.toLowerCase().replace(/[^a-z0-9]+/g, '-')}.png`;
  link.href = canvas.toDataURL('image/png');
  link.click();
}

function wrapCanvasText(ctx, text, x, y, maxWidth, lineHeight) {
  const words = text.split(' ');
  let line = '';
  for (let n = 0; n < words.length; n += 1) {
    const testLine = line + words[n] + ' ';
    const metrics = ctx.measureText(testLine);
    if (metrics.width > maxWidth && n > 0) {
      ctx.fillText(line.trim(), x, y);
      line = words[n] + ' ';
      y += lineHeight;
    } else {
      line = testLine;
    }
  }
  ctx.fillText(line.trim(), x, y);
}

enterPlatform.addEventListener('click', enterTour);
visitorName.addEventListener('keydown', event => {
  if (event.key === 'Enter') enterTour();
});

navLinks.forEach(link => {
  link.addEventListener('click', event => {
    event.preventDefault();
    showSection(link.dataset.section);
  });
});

document.querySelectorAll('[data-jump]').forEach(button => {
  button.addEventListener('click', () => showSection(button.dataset.jump));
});

startTour.addEventListener('click', () => showTourStep(0));
tourSkip.addEventListener('click', finishTour);
tourPrev.addEventListener('click', () => showTourStep(Math.max(0, state.currentStep - 1)));
tourNext.addEventListener('click', () => {
  if (state.currentStep >= tourSteps.length - 1) {
    finishTour();
  } else {
    showTourStep(state.currentStep + 1);
  }
});

openCertificate.addEventListener('click', showCertificate);
completeTour.addEventListener('click', finishTour);
closeCertificate.addEventListener('click', hideCertificate);
downloadCertificate.addEventListener('click', downloadCertificatePng);
certificateModal.addEventListener('click', event => {
  if (event.target === certificateModal) hideCertificate();
});
