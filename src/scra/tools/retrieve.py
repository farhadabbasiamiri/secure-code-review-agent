"""retrieve_guidance tool: RAG over the curated OWASP/CWE knowledge base.

TF-IDF (word 1-2 grams) with cosine similarity. When the caller knows the vulnerability class
and CWE (it usually does, from Semgrep metadata), entries for that class get a boost and the
exact CWE entry is always included — so citations are on-topic even for terse queries.
"""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

KB_PATH = Path(__file__).resolve().parents[3] / "data" / "kb" / "owasp_cwe.json"
CLASS_BOOST = 0.25


class KnowledgeBase:
    def __init__(self, path: Path = KB_PATH):
        self.entries: list[dict] = json.loads(path.read_text())["entries"]
        self.by_id = {e["id"]: e for e in self.entries}
        docs = [
            f"{e['title']} {e['vuln_class'].replace('_', ' ')} {e.get('keywords', '')} {e['text']}"
            for e in self.entries
        ]
        self.vectorizer = TfidfVectorizer(ngram_range=(1, 2), sublinear_tf=True, stop_words="english")
        self.matrix = self.vectorizer.fit_transform(docs)

    def search(self, query: str, vuln_class: str | None = None, cwe: str | None = None, k: int = 3) -> list[dict]:
        scores = cosine_similarity(self.vectorizer.transform([query]), self.matrix)[0]
        ranked = []
        for i, e in enumerate(self.entries):
            s = float(scores[i])
            if vuln_class and e["vuln_class"] == vuln_class:
                s += CLASS_BOOST
            ranked.append((s, e))
        ranked.sort(key=lambda t: t[0], reverse=True)

        results: list[dict] = []
        if cwe and cwe in self.by_id:
            results.append(self._view(self.by_id[cwe], 1.0))
        for s, e in ranked:
            if len(results) >= k:
                break
            if all(r["id"] != e["id"] for r in results) and s > 0.05:
                results.append(self._view(e, round(s, 3)))
        return results

    @staticmethod
    def _view(e: dict, score: float) -> dict:
        return {"id": e["id"], "title": e["title"], "url": e["url"], "score": score, "text": e["text"]}


@lru_cache(maxsize=1)
def get_kb() -> KnowledgeBase:
    return KnowledgeBase()


def retrieve_guidance(query: str, vuln_class: str | None = None, cwe: str | None = None, k: int = 3) -> list[dict]:
    return get_kb().search(query, vuln_class=vuln_class, cwe=cwe, k=k)
