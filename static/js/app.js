(() => {
  "use strict";

  const form = document.getElementById("analysis-form");
  const textarea = document.getElementById("message-input");
  const analyzeButton = document.getElementById("analyze-button");
  const clearButton = document.getElementById("clear-button");
  const retryButton = document.getElementById("retry-button");
  const formError = document.getElementById("form-error");
  const inputCount = document.getElementById("input-count");
  const maxMessageLength = textarea.maxLength;
  const resultsPanel = document.querySelector(".results-panel");
  const resultState = document.getElementById("result-state");
  const emptyState = document.getElementById("empty-state");
  const loadingState = document.getElementById("loading-state");
  const analysisResult = document.getElementById("analysis-result");
  const errorState = document.getElementById("error-state");
  const errorMessage = document.getElementById("error-message");
  const scoreValue = document.getElementById("score-value");
  const scoreCategory = document.getElementById("score-category");
  const scoreRing = document.getElementById("score-ring");
  const ringValue = document.getElementById("ring-value");
  const ringNumber = document.getElementById("ring-number");
  const indicatorCount = document.getElementById("indicator-count");
  const indicatorList = document.getElementById("indicator-list");
  const recommendationList = document.getElementById("recommendation-list");
  const samples = {
    delivery: "Delivery update: We could not deliver your parcel because a small customs fee is due. Pay within 12 hours to avoid return: http://parcel-status.example.invalid/fee",
    school: "URGENT: Your student account will be suspended today. Confirm your password and student ID now at https://campus-login.example.invalid/verify to keep access.",
    ordinary: "Hi Maya, the study group is meeting in the library at 3:30 tomorrow. I reserved the table near the west windows. See you there!"
  };
  let lastSubmittedMessage = "";
  let requestController = null;

  function updateCount() {
    const count = textarea.value.length;
    inputCount.replaceChildren(document.createTextNode(String(count) + " "));
    const limit = document.createElement("span");
    limit.textContent = `/ ${maxMessageLength.toLocaleString()}`;
    inputCount.appendChild(limit);
    inputCount.classList.toggle("is-near", count > maxMessageLength * 0.9);
  }

  function setView(view) {
    emptyState.hidden = view !== "empty";
    loadingState.hidden = view !== "loading";
    analysisResult.hidden = view !== "result";
    errorState.hidden = view !== "error";
    resultsPanel.dataset.status = view === "result" ? "ready" : view;
    resultsPanel.setAttribute("aria-busy", view === "loading" ? "true" : "false");
    resultState.lastChild.textContent = view === "loading" ? " REVIEWING" : view === "result" ? " REVIEW READY" : view === "error" ? " REVIEW INTERRUPTED" : " AWAITING INPUT";
  }

  function showError(message, inForm) {
    const safeMessage = typeof message === "string" ? message : "Something unexpected happened. Please try again.";
    if (inForm) {
      formError.textContent = safeMessage;
      formError.hidden = false;
      return;
    }
    errorMessage.textContent = safeMessage;
    setView("error");
  }

  function clearFormError() {
    formError.textContent = "";
    formError.hidden = true;
  }

  function createIndicator(item) {
    const card = document.createElement("article");
    card.className = "indicator-card";
    const title = document.createElement("strong");
    title.textContent = typeof item.title === "string" ? item.title : "Signal detected";
    const explanation = document.createElement("p");
    explanation.textContent = typeof item.explanation === "string" ? item.explanation : "Review this pattern in context.";
    const points = document.createElement("span");
    points.className = "indicator-points";
    points.textContent = Number.isFinite(Number(item.points)) ? `+${Number(item.points)} pts` : "";
    const heading = document.createElement("div");
    heading.className = "indicator-heading";
    heading.append(title, points);
    card.append(heading, explanation);
    return card;
  }

  function renderResult(data) {
    if (!data || typeof data !== "object" || Array.isArray(data)) {
      throw new Error("The analysis service returned an unexpected response.");
    }
    const numericScore = Number(data.score);
    if (!Number.isFinite(numericScore)) {
      throw new Error("The analysis response did not include a valid score.");
    }
    const score = Math.max(0, Math.min(100, Math.round(numericScore)));
    const indicators = Array.isArray(data.indicators) ? data.indicators : [];
    const recommendations = Array.isArray(data.recommendations) ? data.recommendations : [];
    const category = typeof data.category === "string" && data.category.trim()
      ? data.category.trim()
      : "Estimate unavailable";

    scoreValue.textContent = String(score);
    ringNumber.textContent = String(score);
    scoreCategory.textContent = category;
    scoreRing.setAttribute("aria-label", `Estimated risk score: ${score} out of 100`);
    const circumference = 2 * Math.PI * 47;
    ringValue.setAttribute("stroke-dashoffset", String(circumference * (1 - score / 100)));
    analysisResult.classList.remove("risk-low", "risk-medium", "risk-high");
    analysisResult.classList.add(score >= 75 ? "risk-high" : score >= 25 ? "risk-medium" : "risk-low");

    indicatorList.replaceChildren();
    const validIndicators = indicators.filter((item) => item && typeof item === "object" && !Array.isArray(item));
    indicatorCount.textContent = String(validIndicators.length);
    if (validIndicators.length) {
      validIndicators.forEach((item) => indicatorList.appendChild(createIndicator(item)));
    } else {
      const empty = document.createElement("p");
      empty.className = "no-indicators";
      empty.textContent = "No specific indicators were returned. This does not establish that the message is safe.";
      indicatorList.appendChild(empty);
    }

    recommendationList.replaceChildren();
    const validRecommendations = recommendations.filter((item) => typeof item === "string" && item.trim());
    if (validRecommendations.length) {
      validRecommendations.forEach((recommendation) => {
        const li = document.createElement("li");
        li.textContent = recommendation;
        recommendationList.appendChild(li);
      });
    } else {
      const li = document.createElement("li");
      li.textContent = "Verify unexpected requests using contact details from a trusted source.";
      recommendationList.appendChild(li);
    }
    setView("result");
  }

  async function analyze(message) {
    const value = typeof message === "string" ? message : textarea.value;
    if (!value.trim()) {
      textarea.focus();
      showError("Add a message before starting the review.", true);
      return;
    }
    if (value.length > maxMessageLength) {
      showError(`This message is too long. Please use ${maxMessageLength.toLocaleString()} characters or fewer.`, true);
      return;
    }
    clearFormError();
    lastSubmittedMessage = value;
    if (requestController) requestController.abort();
    requestController = new AbortController();
    analyzeButton.disabled = true;
    analyzeButton.classList.add("is-busy");
    analyzeButton.querySelector(".button-label").textContent = "Reviewing message";
    setView("loading");

    try {
      const response = await fetch("/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json", "Accept": "application/json" },
        body: JSON.stringify({ message: value }),
        signal: requestController.signal
      });
      let payload;
      try {
        payload = await response.json();
      } catch {
        throw new Error("The analysis service returned an unreadable response. Please try again.");
      }
      if (!response.ok) {
        const messageText = payload && typeof payload.error === "string"
          ? payload.error
          : payload && typeof payload.message === "string"
            ? payload.message
            : `The analysis service could not review this message (HTTP ${response.status}).`;
        throw new Error(messageText);
      }
      renderResult(payload);
    } catch (error) {
      if (error && error.name === "AbortError") return;
      const messageText = error instanceof TypeError
        ? "We couldn't reach the analysis service. Check your connection and try again."
        : error instanceof Error
          ? error.message
          : "Something unexpected happened. Please try again.";
      errorMessage.textContent = messageText;
      setView("error");
    } finally {
      analyzeButton.disabled = false;
      analyzeButton.classList.remove("is-busy");
      analyzeButton.querySelector(".button-label").textContent = "Analyze message";
    }
  }

  form.addEventListener("submit", (event) => {
    event.preventDefault();
    analyze(textarea.value);
  });
  textarea.addEventListener("input", () => {
    updateCount();
    if (!formError.hidden) clearFormError();
  });
  clearButton.addEventListener("click", () => {
    if (requestController) requestController.abort();
    textarea.value = "";
    updateCount();
    clearFormError();
    lastSubmittedMessage = "";
    setView("empty");
    textarea.focus();
  });
  document.querySelectorAll("[data-sample]").forEach((button) => {
    button.addEventListener("click", () => {
      textarea.value = samples[button.dataset.sample] || "";
      updateCount();
      clearFormError();
      textarea.focus();
    });
  });
  retryButton.addEventListener("click", () => analyze(lastSubmittedMessage));
  updateCount();
})();
