from src.export import ExportMeta, to_csv, to_html
from src.llm import LlmClient, parse_model_output


def test_csv_and_html_include_only_the_result_columns():
    columns = ["product", "revenue_usd"]
    rows = [{"product": "Atlas", "revenue_usd": 12.5, "secret": "hidden"}]
    csv_text = to_csv(columns, rows).decode("utf-8-sig")
    assert "product,revenue_usd" in csv_text
    assert "Atlas" in csv_text
    assert "secret" not in csv_text
    assert "hidden" not in csv_text
    html = to_html(
        columns,
        rows,
        ExportMeta(
            question="revenue <script>",
            tables=("revenue",),
            sql="SELECT 1",
            assumptions="Last 90 days.",
            generated_at="2026-10-13T00:00:00Z",
            truncated=False,
            username="analyst",
        ),
        {"product": "Product", "revenue_usd": "Revenue"},
    ).decode("utf-8")
    assert "Atlas" in html
    assert "hidden" not in html
    assert "<script>" not in html
    assert "revenue &lt;script&gt;" in html
    assert "Product" in html


def test_csv_does_not_treat_negative_numbers_as_formulas():
    text = to_csv(["revenue_usd"], [{"revenue_usd": -12.5}]).decode("utf-8-sig")
    assert "-12.5" in text


def test_parse_model_output_accepts_json_and_fences():
    sql, note = parse_model_output('{"sql": "SELECT 1 FROM revenue", "assumptions": "all rows"}')
    assert sql == "SELECT 1 FROM revenue"
    assert note == "all rows"
    fenced, _ = parse_model_output("```sql\nSELECT * FROM revenue\n```")
    assert "SELECT * FROM revenue" in fenced
    empty, why = parse_model_output('{"sql": "", "assumptions": "need a date column"}')
    assert empty == ""
    assert "date" in why


def test_client_redacts_the_api_key_from_errors():
    def post(url, headers, json, timeout):
        class Response:
            status_code = 401
            text = "bad key sk-test-secret"

            def json(self):
                return {}

        assert headers["Authorization"] == "Bearer sk-test-secret"
        assert "sk-test-secret" not in str(json)
        assert url.endswith("/chat/completions")
        return Response()

    client = LlmClient("sk-test-secret", "https://openrouter.ai/api/v1", "stub", post=post)
    try:
        client.complete([{"role": "user", "content": "revenue by product"}])
    except Exception as exc:
        message = str(exc)
    else:
        raise AssertionError("expected an error")
    assert "sk-test-secret" not in message
    assert "[redacted]" in message
