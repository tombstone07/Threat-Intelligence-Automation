from openai import OpenAI

client = OpenAI(
  api_key="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"
)

completion = client.chat.completions.create(
  model="gpt-4o-mini",
  store=True,
  messages=[
    {"role": "user", "content": "write a haiku about ai"}
  ]
)

print(completion.choices[0].message);
