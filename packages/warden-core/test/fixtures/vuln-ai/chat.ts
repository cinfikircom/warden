import OpenAI from "openai";
const client = new OpenAI({ apiKey: "sk-proj-abcdefghij1234567890ABCD" });
export async function ask(req: { body: { question: string } }) {
  const prompt = "You are helpful. Answer: " + req.body.question;
  return client.chat.completions.create({ model: "gpt-4", messages: [{ role: "user", content: prompt }] });
}
