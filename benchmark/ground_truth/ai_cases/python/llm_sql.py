"""LLM completion text executed as SQL (TNT-LLMOUT-001, CWE-89)."""

import sqlite3

from openai import OpenAI

client = OpenAI()
db = sqlite3.connect("app.db")


def answer(question: str):
    response = client.chat.completions.create(
        model="gpt-4o", messages=[{"role": "user", "content": question}]
    )
    sql = response.choices[0].message.content
    cursor = db.cursor()
    cursor.execute(sql)
    return cursor.fetchall()
