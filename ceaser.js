// caesarCipher.js

function caesarEncrypt(text, shift) {
  return text
    .split('')
    .map(char => shiftChar(char, shift))
    .join('');
}

function caesarDecrypt(text, shift) {
  return text
    .split('')
    .map(char => shiftChar(char, -shift))
    .join('');
}

function shiftChar(char, shift) {
  const isUpper = char >= 'A' && char <= 'Z';
  const isLower = char >= 'a' && char <= 'z';

  if (isUpper) {
    return String.fromCharCode(((char.charCodeAt(0) - 65 + shift + 26) % 26) + 65);
  }

  if (isLower) {
    return String.fromCharCode(((char.charCodeAt(0) - 97 + shift + 26) % 26) + 97);
  }

  // Non-alphabetical characters are returned as-is
  return char;
}

// === Example Usage ===
const plainText = "Hello, World!";
const shift = 3;

const encrypted = caesarEncrypt(plainText, shift);
const decrypted = caesarDecrypt(encrypted, shift);

console.log("Plaintext :", plainText);
console.log("Encrypted :", encrypted);
console.log("Decrypted :", decrypted);