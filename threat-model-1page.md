# Lab 8 - Báo cáo Mô hình Hiểm họa 1 trang (Threat Model)

## 1. Tài sản cần bảo vệ (Assets)

Trong mô hình truyền dữ liệu lai qua Socket TCP của Lab 8, các tài sản cốt lõi cần được bảo vệ an toàn bao gồm:
- **Tính bí mật của nội dung bản tin (Plaintext):** Thông điệp gốc trao đổi giữa Sender và Receiver không được phép để lộ cho bên thứ ba.
- **Khóa phiên đối xứng (DES Session Key):** Khóa dùng để mã hóa trực tiếp bản tin. Nếu lộ khóa này, toàn bộ nội dung mã hóa sẽ bị giải mã hàng loạt.
- **Khóa bí mật RSA của Receiver (`receiver_private.pem`):** Thành phần tối mật đóng vai trò giải mã khóa phiên DES. Nếu lộ khóa này, toàn bộ hệ thống lai sẽ hoàn toàn sụp đổ.
- **Tính toàn vẹn của gói tin nhị phân (Packet Integrity):** Cấu trúc và luồng byte của gói tin khi truyền trên đường truyền mạng công khai không được phép bị bóp méo, tiêm mã độc hoặc chỉnh sửa bit.

## 2. Đối tượng tấn công giả định (Threat Actor Profile)

Mô hình hiểm họa này giả định kẻ tấn công đứng ở vị trí **Man-in-the-Middle (MitM)** trên kênh truyền mạng giữa Sender và Receiver:
- **Khả năng của kẻ tấn công:** Có khả năng nghe lén (Passive Sniffing) bắt toàn bộ các luồng byte truyền qua Socket TCP, đồng thời có thể can thiệp tích cực (Active Tampering) bằng cách chỉnh sửa bit dữ liệu, cắt bớt gói tin hoặc giả mạo cấu trúc gói tin để gửi đến Receiver.
- **Giới hạn của kẻ tấn công:** Kẻ tấn công không sở hữu khóa bí mật RSA cá nhân của Receiver và không có quyền truy cập vật lý vào bộ nhớ RAM của hai đầu endpoint để đánh cắp khóa rõ.

## 3. Rủi ro và cơ chế giảm thiểu (Risks & Mitigations)

Hệ thống ứng dụng mô hình mật mã lai để xử lý các rủi ro an ninh mạng theo bảng dưới đây:

| Mục tiêu / Rủi ro | Mối đe dọa (STRIDE) | Cơ chế giảm thiểu cụ thể trong Lab 8 |
| :--- | :--- | :--- |
| **Nghe lén nội dung bản tin** | Tam dò thông tin (Information Disclosure) | Sử dụng thuật toán đối xứng **DES ở chế độ CBC** kết hợp vectơ khởi tạo (IV) ngẫu nhiên để biến đổi hoàn toàn plaintext thành bản mã xáo trộn, ngăn chặn hacker đọc hiểu dữ liệu rõ khi bắt được gói tin trên mạng. |
| **Lộ khóa phiên trên kênh truyền** | Tam dò thông tin (Information Disclosure) | Áp dụng cơ chế **RSA-OAEP**. Khóa phiên DES 8 byte không bao giờ được gửi rõ, mà được bọc mã hóa bằng khóa công khai của Receiver. Chỉ duy nhất Receiver giữ khóa bí mật mới giải mã ngược lại được. |
| **Can thiệp, sửa đổi bản mã** | Sửa đổi dữ liệu (Tampering) | Tích hợp hàm băm **SHA-256**. Bản tin plaintext trước khi gửi được băm để tạo mã kiểm tra 32 byte bọc ở cuối gói tin. Receiver sau khi giải mã sẽ tính toán đối chiếu lại để phát hiện ngay hành vi sửa bit. |
| **Tấn công tràn viền / sai cấu trúc** | Từ chối dịch vụ (DoS) / Khai thác lỗi | Thiết kế tiêu đề **Header độ dài 4 byte (Network byte order)** để cố định không gian phân tích cú pháp nhị phân (`parse_secure_packet`). Hàm `recv_exact` bóp chặt số byte nhận, chặn đứng nguy cơ treo socket. |

## 4. Hạn chế còn tồn tại (Residual Risks)

Mặc dù giải quyết được các bài toán cơ bản, mô hình trong bài Lab vẫn còn tồn tại các lỗ hổng bảo mật sau:
- **Điểm yếu thuật toán lõi:** Thuật toán DES có không gian khóa quá ngắn (56 bit hiệu lực), dễ dàng bị phá vỡ bằng các cuộc tấn công vét cạn (Brute-force) bằng phần cứng chuyên dụng ngày nay.
- **Lỗ hổng xác thực nguồn gốc (Authentication):** Hệ thống mới chỉ bảo vệ khóa bằng khóa công khai của Receiver. Tuy nhiên, Receiver hoàn toàn không biết ai là người gửi thực sự (Sender ẩn danh), dẫn đến nguy cơ kẻ tấn công giả mạo làm Sender để gửi mã độc đã mã hóa bằng khóa công khai của Receiver.
- **Tấn công phát lại (Replay Attack):** Gói tin nhị phân không chứa các tham số thời gian (Timestamp) hoặc số ngẫu nhiên dùng một lần (Nonce). Kẻ tấn công có thể bắt lại gói tin hợp lệ và gửi lại liên tục cho Receiver để làm nhiễu loạn hệ thống.
- **Kiểm tra tính toàn vẹn muộn:** Cơ chế SHA-256 rời rạc yêu cầu Receiver phải thực hiện giải mã hoàn chỉnh ra plaintext rồi mới đối chiếu băm. Điều này khiến hệ thống tốn tài nguyên xử lý dữ liệu giả mạo trước khi nhận ra tệp bị hỏng.

## 5. Hướng cải tiến hệ thống

- **Nâng cấp thuật toán đối xứng:** Thay thế hoàn toàn DES bằng **AES-GCM (Mã hóa xác thực)** để vừa bảo mật dữ liệu với không gian khóa lớn (128/256 bit), vừa tích hợp sẵn mã xác thực GMAC giúp Receiver kiểm tra tính toàn vẹn ngay trên tầng bản mã mà không cần giải mã thô.
- **Tích hợp Chữ ký số (Digital Signature):** Yêu cầu Sender ký một chuỗi băm của gói tin bằng khóa bí mật RSA của riêng mình. Receiver sẽ dùng khóa công khai của Sender để xác minh danh tính và chống chối bỏ (Non-repudiation).
- **Chống Replay Attack:** Bổ sung trường dữ liệu `Timestamp` hoặc chuỗi `Nonce` tăng dần vào bên trong gói tin nhị phân truyền qua socket để Receiver kiểm tra tính tuần tự của phiên làm việc.