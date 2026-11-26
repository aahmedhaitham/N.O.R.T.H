const form = document.querySelector('form');
const button = form.querySelector('button');
const message = form.querySelector('[role=alert]');
form.addEventListener('submit', async (event) => {
  event.preventDefault();
  button.disabled = true;
  message.textContent = '';
  try {
    message.textContent = await window.north.connect(new FormData(form).get('address')) ?? '';
  } catch {
    message.textContent = desktopMessages.connectFailed;
  } finally {
    button.disabled = false;
  }
});
document.title = desktopMessages.setupTitle;
for (const element of document.querySelectorAll('[data-message]')) {
  element.textContent = desktopMessages[element.dataset.message];
}
