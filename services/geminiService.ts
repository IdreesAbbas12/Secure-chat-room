
import { GoogleGenAI } from "@google/genai";

const ai = new GoogleGenAI({ apiKey: process.env.API_KEY });

export async function getSecurityAudit(message: string, context: string) {
  try {
    const response = await ai.models.generateContent({
      model: 'gemini-3-flash-preview',
      contents: `Audit the following message for sensitive data leakage or security concerns in a secure chat context. 
      Message: "${message}"
      Context: ${context}
      
      Respond in a concise, friendly manner as a "Security Auditor Bot".`,
      config: {
        systemInstruction: "You are a CipherChat Security Auditor. Your job is to ensure users communicate safely. If a message seems risky (passwords, PII), warn them. Otherwise, provide helpful security tips.",
      },
    });
    return response.text;
  } catch (error) {
    console.error("Gemini Audit Error:", error);
    return "Audit service temporarily unavailable. Communication remains encrypted locally.";
  }
}

export async function getAIAssistantResponse(userPrompt: string) {
  try {
    const response = await ai.models.generateContent({
      model: 'gemini-3-flash-preview',
      contents: userPrompt,
      config: {
        systemInstruction: "You are a helpful AI assistant inside a secure chat room. You explain cryptography (AES-256, SHA-256) and help users understand their privacy features.",
      },
    });
    return response.text;
  } catch (error) {
    console.error("Gemini Error:", error);
    return "I'm having trouble connecting to the secure brain. Try again later.";
  }
}
