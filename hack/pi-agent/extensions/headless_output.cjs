const ANSI_PATTERN = /[\u001b\u009b][\[()#;?]*(?:[0-9]{1,4}(?:;[0-9]{0,4})*)?[0-9A-ORZcf-nry=/><]/g;
const MARKER_LINE_PATTERN = /^5UTR4\b[:\-]?\s*(.*)$/i;

const isNoiseLine = (line) => {
  if (!line) return true;
  if (line.startsWith("Tokens:")) return true;
  if (line.includes("Warning: Input is not a terminal")) return true;
  return false;
};

const stripAnsi = (str) => str.replace(ANSI_PATTERN, "");

const extractHeadlessFinalAnswer = (rawOutput) => {
  const cleanText = stripAnsi(String(rawOutput || "")).replace(/\r\n/g, "\n").replace(/\r/g, "\n");
  const lines = cleanText.split("\n");

  for (let i = lines.length - 1; i >= 0; i -= 1) {
    const match = lines[i].trim().match(MARKER_LINE_PATTERN);
    if (!match) continue;

    const inlineAnswer = match[1].trim();
    if (inlineAnswer) {
      return inlineAnswer;
    }

    const trailingLines = [];
    for (let j = i + 1; j < lines.length; j += 1) {
      const trimmedLine = lines[j].trim();
      if (isNoiseLine(trimmedLine)) continue;
      trailingLines.push(trimmedLine);
    }

    const trailingAnswer = trailingLines.join("\n").trim();
    if (trailingAnswer) {
      return trailingAnswer;
    }
  }

  return "";
};

module.exports = {
  extractHeadlessFinalAnswer,
  stripAnsi
};
