document.addEventListener('DOMContentLoaded', () => {
  const toggleBtn = document.getElementById("toggleBtn");
  const statusEl  = document.getElementById("status");

  chrome.storage.local.get("isActive", (data) => {
    renderToggleUI(data.isActive !== false);
  });

  toggleBtn.addEventListener("click", () => {
    chrome.storage.local.get("isActive", (data) => {
      const newState = !(data.isActive !== false);
      chrome.storage.local.set({ isActive: newState });
      renderToggleUI(newState);
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (tabs[0]?.id) {
          chrome.tabs.sendMessage(tabs[0].id, { action: "TOGGLE_WIDGET", state: newState }, () => {
            if (chrome.runtime.lastError) {}
          });
        }
      });
    });
  });

  function renderToggleUI(isOn) {
    toggleBtn.innerText = isOn ? "Turn OFF"        : "Turn ON";
    toggleBtn.className = isOn ? "btn-off"         : "btn-on";
    statusEl.innerText  = isOn ? "Shield is ACTIVE" : "Shield is SLEEPING";
    statusEl.className  = isOn ? ""                : "off";
  }
});
