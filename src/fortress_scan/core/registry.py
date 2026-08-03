from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, Tuple

from .model import Category, Confidence, Severity


@dataclass(frozen=True)
class RuleSpec:
    id: str
    title: str
    category: Category
    severity: Severity
    confidence: Confidence
    cwe: Tuple[str, ...]
    owasp: Tuple[str, ...]
    description: str
    remediation: str
    references: Tuple[str, ...] = ()


_OWASP_INJECTION = ("A03:2021-Injection",)
_OWASP_INTEGRITY = ("A08:2021-Software and Data Integrity Failures",)

_RULE_LIST: Tuple[RuleSpec, ...] = (
    RuleSpec(
        id="FSB-EXEC-001",
        title="Dữ liệu không tin cậy chạy tới nơi thực thi mã động",
        category=Category.CODE_EXECUTION,
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        cwe=("CWE-94", "CWE-95"),
        owasp=_OWASP_INJECTION,
        description=(
            "Một giá trị có nguồn gốc từ bên ngoài, kẻ tấn công điều khiển được, chảy vào lệnh "
            "biên dịch hoặc thực thi mã lúc chạy. Ai chi phối được giá trị đó sẽ chạy được mã tùy "
            "ý ngay bên trong tiến trình ứng dụng."
        ),
        remediation=(
            "Đừng đem dữ liệu ra thực thi như mã. Thay bằng bảng ánh xạ (dict) các hành động cho "
            "phép, hoặc viết bộ phân tích cho đúng cú pháp bạn cần. Nếu chỉ cần một con số thì ép "
            "kiểu bằng int()/float(); nếu cần đọc một literal thì dùng ast.literal_eval() trên dữ "
            "liệu đã kiểm tra trước."
        ),
        references=("https://cwe.mitre.org/data/definitions/95.html",),
    ),
    RuleSpec(
        id="FSB-EXEC-002",
        title="Thực thi mã động từ biểu thức không phải hằng",
        category=Category.CODE_EXECUTION,
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        cwe=("CWE-94",),
        owasp=_OWASP_INJECTION,
        description=(
            "Mã được biên dịch hoặc thực thi từ một giá trị mà bộ phân tích không chứng minh được "
            "là hằng số. Chưa thấy đường đi từ nguồn không tin cậy nào, nên đây là điểm yếu thiết "
            "kế cần rà lại, chưa phải lỗ hổng đã xác nhận."
        ),
        remediation=(
            "Ưu tiên cách làm tĩnh. Nếu buộc phải thực thi động, hãy bảo đảm giá trị đầu vào chỉ "
            "được tạo từ dữ liệu do chính chương trình kiểm soát."
        ),
    ),
    RuleSpec(
        id="FSB-CMD-001",
        title="Dữ liệu không tin cậy chạy vào câu lệnh được shell diễn giải",
        category=Category.COMMAND,
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        cwe=("CWE-78",),
        owasp=_OWASP_INJECTION,
        description=(
            "Dữ liệu kẻ tấn công điều khiển được nối vào chuỗi lệnh rồi đưa cho shell hệ điều "
            "hành. Các ký tự đặc biệt của shell như ; | & $() ` và xuống dòng cho phép kẻ tấn công "
            "gắn thêm lệnh tùy ý, chạy với đúng quyền của ứng dụng."
        ),
        remediation=(
            "Truyền chương trình và từng tham số thành các phần tử riêng trong danh sách, và tắt "
            "shell (ví dụ subprocess.run([\"git\", \"clone\", url]) với shell=False). Nếu thật sự "
            "cần shell, hãy bọc mọi giá trị chèn vào bằng shlex.quote() và kiểm tra nó theo danh "
            "sách trắng trước."
        ),
        references=("https://cwe.mitre.org/data/definitions/78.html",),
    ),
    RuleSpec(
        id="FSB-CMD-002",
        title="Dữ liệu không tin cậy quyết định chương trình hoặc tham số được chạy",
        category=Category.COMMAND,
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        cwe=("CWE-78", "CWE-88"),
        owasp=_OWASP_INJECTION,
        description=(
            "Dữ liệu kẻ tấn công điều khiển được đi tới chỗ tạo tiến trình mà không qua shell. Kẻ "
            "tấn công không nối thêm được lệnh, nhưng vẫn chọn được binary nào sẽ chạy hoặc chèn "
            "thêm cờ tùy chọn vào danh sách tham số, và điều này thường leo thang thành chạy mã."
        ),
        remediation=(
            "Lấy đường dẫn chương trình từ danh sách trắng cố định, đừng lấy từ đầu vào. Chèn dấu "
            "phân cách \"--\" trước các giá trị do người dùng cung cấp để chúng không bị hiểu là "
            "cờ tùy chọn, và kiểm tra định dạng từng tham số."
        ),
    ),
    RuleSpec(
        id="FSB-CMD-003",
        title="Câu lệnh shell được ghép từ biểu thức không phải hằng",
        category=Category.COMMAND,
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        cwe=("CWE-78",),
        owasp=_OWASP_INJECTION,
        description=(
            "Chuỗi lệnh đưa cho shell được ghép lúc chạy từ những giá trị không chứng minh được là "
            "hằng. Chưa thấy nguồn không tin cậy nào chạm tới, nhưng đây đúng là kiểu ghép chuỗi "
            "sinh ra lỗi command injection."
        ),
        remediation=(
            "Tắt shell và truyền danh sách tham số. Nếu bắt buộc dùng shell, hãy ghép lệnh chỉ từ "
            "hằng số và bọc mọi phần biến đổi bằng shlex.quote()."
        ),
    ),
    RuleSpec(
        id="FSB-CMD-004",
        title="Biến shell được khai triển mà không đặt trong nháy kép",
        category=Category.COMMAND,
        severity=Severity.MEDIUM,
        confidence=Confidence.LOW,
        cwe=("CWE-78",),
        owasp=_OWASP_INJECTION,
        description=(
            "Script shell khai triển một biến mà không bọc nháy kép. Giá trị sẽ bị tách từ theo "
            "khoảng trắng và bị khai triển ký tự đại diện, nên đầu vào chứa khoảng trắng hay ký tự "
            "đặc biệt sẽ làm thay đổi cấu trúc câu lệnh đang chạy."
        ),
        remediation=(
            "Bọc mọi khai triển trong nháy kép (\"$var\", \"${arr[@]}\"). Ưu tiên mảng thay cho "
            "chuỗi ngăn cách bằng khoảng trắng, và dùng printf %q khi giá trị phải đi qua một "
            "shell lồng bên trong."
        ),
    ),
    RuleSpec(
        id="FSB-SQL-001",
        title="Dữ liệu không tin cậy được nối thẳng vào câu lệnh SQL",
        category=Category.SQL,
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        cwe=("CWE-89",),
        owasp=_OWASP_INJECTION,
        description=(
            "Dữ liệu kẻ tấn công điều khiển được trở thành một phần của chính câu SQL gửi xuống cơ "
            "sở dữ liệu, thay vì được truyền vào như tham số. Kẻ tấn công đổi được ý nghĩa câu "
            "truy vấn, đọc hoặc sửa dữ liệu tùy ý, và trên nhiều hệ quản trị còn với được tới hệ "
            "điều hành."
        ),
        remediation=(
            "Dùng tham số ràng buộc và giữ nguyên phần chữ của câu lệnh: "
            "cursor.execute(\"SELECT * FROM users WHERE id = %s\", (user_id,)). Tên bảng và tên "
            "cột không ràng buộc được, nên phải ánh xạ qua danh sách trắng cố định trong mã."
        ),
        references=("https://cwe.mitre.org/data/definitions/89.html",),
    ),
    RuleSpec(
        id="FSB-SQL-002",
        title="Câu lệnh SQL được ghép bằng định dạng chuỗi",
        category=Category.SQL,
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        cwe=("CWE-89",),
        owasp=_OWASP_INJECTION,
        description=(
            "Câu SQL được dựng bằng nối chuỗi, %-format, str.format hoặc f-string. Chưa chứng minh "
            "được nguồn không tin cậy nào chạm tới, nhưng phần chữ của câu lệnh không còn là hằng "
            "và chỉ cách một lần sửa nữa là thành lỗ hổng."
        ),
        remediation=(
            "Đưa mọi phần biến đổi của câu lệnh vào tham số ràng buộc, để bản thân câu SQL luôn là "
            "một chuỗi hằng."
        ),
    ),
    RuleSpec(
        id="FSB-NOSQL-001",
        title="Dữ liệu không tin cậy chạy vào toán tử truy vấn NoSQL",
        category=Category.NOSQL,
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        cwe=("CWE-943",),
        owasp=_OWASP_INJECTION,
        description=(
            "Dữ liệu kẻ tấn công điều khiển được đi vào truy vấn document store ở vị trí chấp nhận "
            "toán tử hoặc JavaScript chạy phía máy chủ. Chỉ cần gửi một object thay vì giá trị đơn "
            "là kẻ tấn công thay được phép so sánh bằng $ne, $gt hay $where và vượt qua bộ lọc."
        ),
        remediation=(
            "Ép mọi giá trị truy vấn về đúng kiểu vô hướng bạn mong đợi trước khi dựng bộ lọc, từ "
            "chối các khóa bắt đầu bằng \"$\", và tuyệt đối không bật JavaScript phía máy chủ như "
            "$where hay db.eval."
        ),
    ),
    RuleSpec(
        id="FSB-LDAP-001",
        title="Dữ liệu không tin cậy chạy vào bộ lọc LDAP",
        category=Category.LDAP,
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        cwe=("CWE-90",),
        owasp=_OWASP_INJECTION,
        description=(
            "Dữ liệu kẻ tấn công điều khiển được nhúng vào bộ lọc tìm kiếm LDAP hoặc tên phân biệt "
            "(DN). Các ký tự như * ( ) \\ và NUL làm đổi cấu trúc bộ lọc, có thể dùng để liệt kê "
            "toàn bộ thư mục hoặc vượt qua xác thực."
        ),
        remediation=(
            "Escape mọi giá trị chèn vào bằng hàm escape bộ lọc theo RFC 4515 mà thư viện LDAP của "
            "bạn cung cấp, và kiểm tra riêng từng thành phần của DN."
        ),
    ),
    RuleSpec(
        id="FSB-XPATH-001",
        title="Dữ liệu không tin cậy chạy vào biểu thức XPath",
        category=Category.XPATH,
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        cwe=("CWE-643",),
        owasp=_OWASP_INJECTION,
        description=(
            "Dữ liệu kẻ tấn công điều khiển được nối vào biểu thức XPath, cho phép viết lại điều "
            "kiện lọc và đọc những nút nằm ngoài phạm vi dự định."
        ),
        remediation=(
            "Dùng cơ chế ràng buộc biến của engine XPath (ví dụ biến XPath trong lxml) thay cho "
            "nối chuỗi."
        ),
    ),
    RuleSpec(
        id="FSB-TMPL-001",
        title="Dữ liệu không tin cậy được biên dịch thành template",
        category=Category.TEMPLATE,
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        cwe=("CWE-1336", "CWE-94"),
        owasp=_OWASP_INJECTION,
        description=(
            "Dữ liệu kẻ tấn công điều khiển được trở thành mã nguồn của template chứ không phải dữ "
            "liệu truyền vào template. Các engine template phía máy chủ cho phép duyệt ngược đối "
            "tượng, nên lỗi này gần như luôn leo thang thành chạy mã từ xa."
        ),
        remediation=(
            "Giữ nguồn template cố định và truyền dữ liệu người dùng qua context khi render "
            "(render_template(\"page.html\", name=name) thay vì render_template_string(dl_nguoi_dung)). "
            "Nếu bắt buộc cho người dùng gửi template, hãy render trong môi trường sandbox với "
            "danh sách trắng thuộc tính."
        ),
        references=("https://cwe.mitre.org/data/definitions/1336.html",),
    ),
    RuleSpec(
        id="FSB-TMPL-002",
        title="Template được biên dịch từ biểu thức không phải hằng",
        category=Category.TEMPLATE,
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        cwe=("CWE-1336",),
        owasp=_OWASP_INJECTION,
        description=(
            "Một template được biên dịch từ giá trị không phải hằng. Chưa thấy nguồn không tin cậy "
            "nào chạm tới, nhưng đây là điểm sẽ thành lỗi template injection ngay khi giá trị đó "
            "chịu ảnh hưởng từ người dùng."
        ),
        remediation=(
            "Nạp template từ loader và thư mục cố định, thay vì biên dịch chuỗi dựng lúc chạy."
        ),
    ),
    RuleSpec(
        id="FSB-DESER-001",
        title="Dữ liệu không tin cậy chạy vào bộ giải tuần tự nguy hiểm",
        category=Category.DESERIALIZATION,
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        cwe=("CWE-502",),
        owasp=_OWASP_INTEGRITY,
        description=(
            "Chuỗi byte kẻ tấn công điều khiển được đưa vào bộ giải tuần tự có khả năng dựng lại "
            "đồ thị đối tượng tùy ý. Các định dạng này gọi hàm khởi tạo trong lúc giải mã, nên một "
            "payload được chế tác sẽ chạy mã trước khi ứng dụng kịp kiểm tra kết quả."
        ),
        remediation=(
            "Dùng định dạng chỉ chứa dữ liệu như JSON, hoặc định dạng nhị phân có kiểm tra schema. "
            "Nếu buộc phải dùng pickle, chỉ áp dụng cho dữ liệu cục bộ tin cậy và ký HMAC cho "
            "payload rồi xác minh trước khi giải mã."
        ),
        references=("https://cwe.mitre.org/data/definitions/502.html",),
    ),
    RuleSpec(
        id="FSB-DESER-002",
        title="Đang dùng bộ giải tuần tự nguy hiểm",
        category=Category.DESERIALIZATION,
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        cwe=("CWE-502",),
        owasp=_OWASP_INTEGRITY,
        description=(
            "Có lời gọi tới bộ giải tuần tự có thể khởi tạo kiểu dữ liệu tùy ý. Chưa truy được đầu "
            "vào về một nguồn không tin cậy, nhưng bất kỳ thay đổi nào sau này khiến byte từ bên "
            "ngoài chạm tới đây đều biến nó thành lỗ hổng chạy mã từ xa."
        ),
        remediation=(
            "Chuyển sang biến thể an toàn mà thư viện cung cấp: yaml.safe_load, json.loads, "
            "torch.load(..., weights_only=True), numpy.load(..., allow_pickle=False)."
        ),
    ),
    RuleSpec(
        id="FSB-IMPORT-001",
        title="Dữ liệu không tin cậy quyết định module hoặc mã được nạp",
        category=Category.DYNAMIC_IMPORT,
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        cwe=("CWE-829", "CWE-98"),
        owasp=_OWASP_INTEGRITY,
        description=(
            "Dữ liệu kẻ tấn công điều khiển được chọn module, tệp hay đường dẫn sẽ được nạp và "
            "thực thi. Nạp một module là chạy mã ở mức cao nhất của module đó, nên điều khiển được "
            "cái tên là điều khiển được việc thực thi."
        ),
        remediation=(
            "Ánh xạ tên được yêu cầu qua một từ điển cố định các module cho phép và từ chối mọi "
            "thứ khác. Tuyệt đối không ghép chuỗi để tạo đường dẫn nạp."
        ),
    ),
    RuleSpec(
        id="FSB-IMPORT-002",
        title="Module được nạp từ biểu thức không phải hằng",
        category=Category.DYNAMIC_IMPORT,
        severity=Severity.LOW,
        confidence=Confidence.LOW,
        cwe=("CWE-829",),
        owasp=_OWASP_INTEGRITY,
        description=(
            "Một module hoặc tệp mã được nạp từ giá trị không phải hằng. Các hệ thống plugin làm "
            "vậy một cách chính đáng; hãy xác nhận tập ứng viên không thể bị tác động từ bên ngoài."
        ),
        remediation=(
            "Giới hạn bộ nạp trong một thư mục cố định do ứng dụng sở hữu và kiểm tra đường dẫn "
            "sau khi phân giải vẫn nằm trong thư mục đó."
        ),
    ),
    RuleSpec(
        id="FSB-REFL-001",
        title="Dữ liệu không tin cậy quyết định thuộc tính hoặc phương thức được gọi",
        category=Category.REFLECTION,
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        cwe=("CWE-470",),
        owasp=_OWASP_INJECTION,
        description=(
            "Dữ liệu kẻ tấn công điều khiển được chọn thuộc tính hoặc phương thức nào sẽ được tra "
            "cứu rồi gọi. Đồ thị đối tượng truy cập được qua các thuộc tính dunder cho phép kẻ tấn "
            "công đi từ một lần tra cứu tùy ý tới việc thực thi tùy ý."
        ),
        remediation=(
            "Điều phối qua một bảng ánh xạ tường minh từ tên được phép sang hàm xử lý. Nếu bắt "
            "buộc dùng reflection, hãy từ chối tên chứa \"_\" và kiểm tra đối tượng thu được đúng "
            "là callable thuộc lớp mong đợi."
        ),
    ),
    RuleSpec(
        id="FSB-EL-001",
        title="Dữ liệu không tin cậy chạy vào bộ đánh giá expression language",
        category=Category.EXPRESSION_LANGUAGE,
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        cwe=("CWE-917",),
        owasp=_OWASP_INJECTION,
        description=(
            "Dữ liệu kẻ tấn công điều khiển được đưa cho engine expression language như SpEL, "
            "OGNL, MVEL hoặc một scripting engine. Các ngôn ngữ này với được tới class loader và "
            "do đó tới cả runtime, dẫn thẳng tới chạy mã từ xa."
        ),
        remediation=(
            "Tuyệt đối không phân tích đầu vào người dùng như một biểu thức. Nếu buộc phải dùng "
            "engine, hãy cấu hình context đánh giá hạn chế, cấm tham chiếu kiểu và cấm gọi phương "
            "thức."
        ),
    ),
    RuleSpec(
        id="FSB-XSS-001",
        title="Dữ liệu không tin cậy chạy vào nơi xuất HTML thô",
        category=Category.MARKUP,
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        cwe=("CWE-79",),
        owasp=_OWASP_INJECTION,
        description=(
            "Dữ liệu kẻ tấn công điều khiển được ghi vào nơi trình duyệt hiểu là HTML chứ không "
            "phải văn bản, cho phép chèn script chạy trong chính origin của ứng dụng."
        ),
        remediation=(
            "Gán qua textContent, để engine template tự escape, hoặc làm sạch bằng một thư viện "
            "sanitizer HTML uy tín cấu hình theo danh sách trắng trước khi gán vào innerHTML."
        ),
    ),
    RuleSpec(
        id="FSB-XML-001",
        title="XML được phân tích với chế độ phân giải thực thể ngoài",
        category=Category.XML,
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        cwe=("CWE-611",),
        owasp=_OWASP_INJECTION,
        description=(
            "Bộ phân tích XML được cấu hình cho phép phân giải thực thể ngoài hoặc nạp DTD. Một "
            "tài liệu được chế tác có thể đọc tệp cục bộ, gọi tới dịch vụ nội bộ trong mạng, hoặc "
            "làm cạn bộ nhớ."
        ),
        remediation=(
            "Tắt nạp DTD và phân giải thực thể trên parser, hoặc dùng thư viện đã gia cố như "
            "defusedxml."
        ),
    ),
    RuleSpec(
        id="FSB-UNI-001",
        title="Ký tự điều khiển hai chiều được nhúng trong mã nguồn",
        category=Category.UNICODE,
        severity=Severity.HIGH,
        confidence=Confidence.CERTAIN,
        cwe=("CWE-94", "CWE-1007"),
        owasp=_OWASP_INTEGRITY,
        description=(
            "Tệp chứa ký tự điều khiển hai chiều (bidi override/isolate) của Unicode. Chúng đảo "
            "thứ tự hiển thị của văn bản mà không đổi cách trình biên dịch đọc, nên logic mà người "
            "review nhìn thấy khác với logic thực sự chạy. Đây chính là kỹ thuật Trojan Source để "
            "tuồn mã độc qua vòng review."
        ),
        remediation=(
            "Gỡ bỏ các ký tự này. Nếu thật sự cần văn bản hai chiều, hãy đưa vào tệp tài nguyên "
            "thay vì mã nguồn, và thêm một bước kiểm tra trong CI để chặn các code point này."
        ),
        references=("https://trojansource.codes/",),
    ),
    RuleSpec(
        id="FSB-UNI-002",
        title="Ký tự vô hình hoặc rộng bằng không trong mã nguồn",
        category=Category.UNICODE,
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        cwe=("CWE-94",),
        owasp=_OWASP_INTEGRITY,
        description=(
            "Tệp chứa các code point vô hình hoặc rộng bằng không. Chúng nấp được bên trong tên "
            "định danh và chuỗi ký tự, khiến hai token trông giống hệt nhau nhưng lại là hai thứ "
            "khác nhau với trình biên dịch."
        ),
        remediation=(
            "Xóa các ký tự này và giới hạn tên định danh trong tập ký tự nhìn thấy được ở khâu lint."
        ),
    ),
    RuleSpec(
        id="FSB-UNI-003",
        title="Token trộn lẫn các bảng chữ cái dễ nhầm",
        category=Category.UNICODE,
        severity=Severity.LOW,
        confidence=Confidence.LOW,
        cwe=("CWE-1007",),
        owasp=_OWASP_INTEGRITY,
        description=(
            "Một token trộn chữ cái từ nhiều bảng trong nhóm Latin, Cyrillic, Greek và Armenian. "
            "Các bảng này có những chữ trông giống hệt nhau: thay chữ a Latin bằng code point "
            "U+0430 của Cyrillic sẽ tạo ra một cái tên nhìn không phân biệt được với bản gốc nhưng "
            "lại là ký hiệu khác với trình biên dịch, đủ để một tên giả mạo che tên thật. Các hệ "
            "chữ không có glyph trùng với Latin, như tiếng Nhật hay tiếng Trung, không bị báo."
        ),
        remediation=(
            "Giữ mỗi token trong một bảng chữ cái duy nhất. Kiểm tra xem cái tên này có đang cố ý "
            "khác với một tên trông tương tự ở nơi khác trong dự án hay không."
        ),
    ),
    RuleSpec(
        id="FSB-SUP-001",
        title="Script vòng đời của package tải mã từ xa về chạy",
        category=Category.SUPPLY_CHAIN,
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        cwe=("CWE-506", "CWE-829"),
        owasp=_OWASP_INTEGRITY,
        description=(
            "Một script chạy lúc cài đặt hoặc build tải nội dung về rồi đẩy thẳng vào trình thông "
            "dịch. Ai kiểm soát được endpoint đó, hoặc chặn được kết nối, sẽ chạy mã trên mọi máy "
            "lập trình viên và mọi máy CI cài package này."
        ),
        remediation=(
            "Đưa phụ thuộc vào trong kho (vendor), ghim theo digest, và xác minh chữ ký trước khi "
            "chạy. Loại bỏ hoàn toàn kiểu tải-về-chạy-ngay trong script vòng đời."
        ),
    ),
    RuleSpec(
        id="FSB-SUP-002",
        title="Script vòng đời của package chạy lệnh shell",
        category=Category.SUPPLY_CHAIN,
        severity=Severity.LOW,
        confidence=Confidence.LOW,
        cwe=("CWE-829",),
        owasp=_OWASP_INTEGRITY,
        description=(
            "Một script chạy lúc cài đặt có gọi lệnh shell. Chuyện này phổ biến và thường hợp lệ, "
            "nhưng đây đúng là cơ chế mà các payload dependency confusion lợi dụng, nên câu lệnh "
            "này đáng để liếc qua."
        ),
        remediation=(
            "Giữ script cài đặt tối giản, và dùng --ignore-scripts trên CI ở những nơi quá trình "
            "build không cần tới chúng."
        ),
    ),
)

RULES: Dict[str, RuleSpec] = {rule.id: rule for rule in _RULE_LIST}


def get_rule(rule_id: str) -> RuleSpec:
    try:
        return RULES[rule_id]
    except KeyError:
        raise KeyError("không có rule với mã: %s" % rule_id) from None


def all_rules() -> Iterable[RuleSpec]:
    return tuple(sorted(_RULE_LIST, key=lambda rule: rule.id))


def rules_digest() -> str:
    import hashlib

    digest = hashlib.sha256()
    for rule in all_rules():
        digest.update(rule.id.encode("utf-8"))
        digest.update(b"\x1f")
        digest.update(rule.title.encode("utf-8"))
        digest.update(b"\x1f")
        digest.update(str(int(rule.severity)).encode("utf-8"))
        digest.update(b"\x1e")
    return digest.hexdigest()
