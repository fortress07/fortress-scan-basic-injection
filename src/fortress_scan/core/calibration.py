"""Hiệu chỉnh độ tin cậy và ghi lại BẰNG CHỨNG cho từng phát hiện.

Bộ phân tích biết vì sao nó bắn, nhưng thứ đó xưa nay chết ngay trong hàm đã
bắn: báo cáo chỉ còn một nhãn "high" trần trụi mà người đọc không kiểm chứng
được. Chỗ này gom lại thành một pha duy nhất chạy sau mọi bộ phân tích, cho
mọi ngôn ngữ:

* dựng danh sách bằng chứng kiểm chứng được bằng mắt trên chính đoạn mã --
  có nguồn không tin cậy hay không, đường đi dài bao nhiêu bước, có đi qua
  ranh giới tệp không, sink có chắc chắn không;
* hạ độ tin cậy đúng một nấc khi ngữ cảnh tệp nói rằng phát hiện ít khẩn hơn
  ( test, ví dụ, mã sinh, mã đi mượn ), và NÓI RA lý do ngay trong phát hiện;
* áp lại ngưỡng --min-confidence sau khi đã hạ, vì ngưỡng lọc phải soi con số
  cuối cùng chứ không phải con số bộ phân tích đưa ra trước khi hiệu chỉnh.

Không có bước nào ở đây được phép NÂNG độ tin cậy: hiệu chỉnh chỉ để bớt kêu
oan, không phải để tự khen.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Dict, List, Sequence, cast

from ..security.text import display_path
from .config import Config
from .context import classify, demotion_reason
from .model import Confidence, Finding, PathContext, StepKind

# Mỗi phát hiện giữ tối đa ngần này dòng bằng chứng. Bằng chứng đi vào JSON và
# SARIF của mọi phát hiện, nên nó là thứ nhân lên theo số phát hiện -- để trôi
# tự do thì một lượt quét lớn phình báo cáo lên vô hạn.
MAX_EVIDENCE = 6

_MAX_EVIDENCE_TEXT = 200


def _step_down(confidence: Confidence) -> Confidence:
    if confidence <= Confidence.LOW:
        return Confidence.LOW
    return Confidence(int(confidence) - 10)


def _flow_evidence(finding: Finding) -> List[str]:
    """Bằng chứng suy từ chính đường đi đã dựng được, không đoán thêm gì."""
    reasons: List[str] = []
    source_steps = [step for step in finding.trace if step.kind is StepKind.SOURCE]
    sink_steps = [step for step in finding.trace if step.kind is StepKind.SINK]

    if source_steps:
        reasons.append(
            "có nguồn dữ liệu không tin cậy xác định được: %s (dòng %d)"
            % (source_steps[0].label, source_steps[0].line)
        )
    else:
        reasons.append(
            "chưa dựng được nguồn không tin cậy cụ thể -- phát hiện dựa trên hình dạng "
            "của chính lời gọi"
        )

    if sink_steps:
        last = sink_steps[-1]
        # display_path() vì đường dẫn này đến từ cây được quét: nó đi vào
        # console qua neutralize() nhưng cũng đi vào Markdown, và trung hoà
        # ngay tại chỗ dựng chuỗi thì không định dạng nào phải tự nhớ.
        where = " ở %s" % display_path(last.path) if last.path else ""
        reasons.append("điểm nguy hiểm: %s (dòng %d%s)" % (last.label, last.line, where))

    if len(finding.trace) > 1:
        reasons.append("đường đi dựng được %d bước" % len(finding.trace))

    if any(step.path for step in finding.trace):
        reasons.append(
            "dữ liệu đi qua ranh giới tệp; đường đi xuyên file là xấp xỉ có chặn trên "
            "nên hãy đối chiếu lại lời gọi trung gian"
        )
    elif "interprocedural" in finding.tags:
        reasons.append("dữ liệu đi qua ít nhất một lời gọi hàm trung gian trong cùng tệp")

    return reasons


def _apply_one(finding: Finding, config: Config) -> Finding:
    context = classify(finding.path)
    reasons: List[str] = list(finding.evidence)
    reasons.extend(_flow_evidence(finding))

    confidence = finding.confidence
    tags = finding.tags
    if context is not PathContext.PRODUCTION:
        tags = tags + ("context:%s" % context.value,)
        reason = demotion_reason(context)
        if config.context_awareness:
            lowered = _step_down(confidence)
            if lowered != confidence and reason:
                reasons.append("hạ một nấc độ tin cậy: %s" % reason)
            confidence = lowered
        elif reason:
            reasons.append("%s (không hạ độ tin cậy vì đã tắt hiệu chỉnh ngữ cảnh)" % reason)

    trimmed = tuple(item[:_MAX_EVIDENCE_TEXT] for item in reasons[:MAX_EVIDENCE])
    # cast() vì dataclasses.replace() được khai báo trả về DataclassInstance
    # chứ không phải kiểu của chính đối tượng đưa vào -- một giới hạn của
    # typeshed, không phải của mã ở đây. Không có nó thì mọi bộ kiểm kiểu đều
    # báo sai kiểu trả về của hàm này.
    return cast(
        Finding,
        replace(finding, confidence=confidence, context=context, tags=tags, evidence=trimmed),
    )


def apply(findings: Sequence[Finding], config: Config) -> List[Finding]:
    """Hiệu chỉnh rồi lọc lại theo ngưỡng cuối cùng.

    Lọc SAU khi hạ là bắt buộc: FindingBuilder đã so ngưỡng với con số trước
    hiệu chỉnh, nên nếu không so lại ở đây thì --min-confidence=high vẫn để
    lọt một phát hiện vừa bị hạ xuống medium -- người dùng đặt ngưỡng mà nhận
    về thứ dưới ngưỡng.
    """
    result: List[Finding] = []
    for finding in findings:
        calibrated = _apply_one(finding, config)
        if calibrated.confidence < config.min_confidence:
            continue
        result.append(calibrated)
    return _number_duplicates(result)


def _number_duplicates(findings: List[Finding]) -> List[Finding]:
    """Đánh số những phát hiện có cùng vân tay, theo thứ tự đọc trong tệp.

    Hai dòng thủng giống hệt nhau trong cùng một tệp vốn cho ra cùng một vân
    tay, và một mục baseline sẽ che cả hai. Nghĩa là người ta thêm một lỗ hổng
    thứ hai mà cổng CI vẫn xanh. Số thứ tự tách chúng ra, còn cái đầu tiên
    giữ nguyên vân tay cũ nên baseline đã ghi vẫn dùng được.

    Đánh số sau khi đã lọc theo ngưỡng, để số thứ tự chỉ phụ thuộc vào những
    phát hiện thật sự có mặt trong báo cáo.
    """
    seen: Dict[str, int] = {}
    numbered: List[Finding] = []
    for finding in sorted(findings, key=lambda item: item.sort_key):
        material = finding.fingerprint_material
        index = seen.get(material, 0)
        seen[material] = index + 1
        numbered.append(finding if index == 0 else replace(finding, occurrence=index))
    return numbered
