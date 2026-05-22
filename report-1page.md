# Lab 8 - Báo cáo 1 trang: Truyền dữ liệu an toàn qua Socket

## 1. Mục tiêu

Mục tiêu của bài thực hành nhằm xây dựng và hoàn thiện một ứng dụng truyền nhận dữ liệu an toàn qua socket TCP dựa trên mô hình mật mã lai (Hybrid Cryptosystem). Hệ thống kết hợp đồng thời ba tầng bảo vệ mật mã:
- **Mã hóa đối xứng (DES-CBC):** Đảm bảo tính bí mật (Confidentiality) cho nội dung bản tin gốc bằng cách mã hóa khối kết hợp đệm cấu trúc PKCS#7.
- **Mã hóa bất đối xứng (RSA-OAEP):** Giải quyết bài toán phân phối khóa an toàn bằng cách sử dụng khóa công khai của Receiver để bọc bảo vệ khóa phiên DES 8-byte trước khi truyền qua Internet.
- **Hàm băm bảo mật (SHA-256):** Đảm bảo tính toàn vẹn (Integrity) của dữ liệu, giúp Receiver phát hiện ngay lập tức mọi hành vi can thiệp hoặc sửa đổi gói tin từ bên ngoài.

## 2. Luồng xử lý Sender

1. **Thu thập dữ liệu đầu vào:** Đọc nội dung thông điệp dạng rõ (plaintext) từ biến môi trường `MESSAGE`, tệp cấu hình `INPUT_FILE` hoặc nhập trực tiếp từ bàn phím người dùng.
2. **Tính toán mã kiểm tra:** Băm chuỗi plaintext gốc bằng thuật toán SHA-256 để sinh ra mã kiểm tra toàn vẹn cố định dài 32 byte.
3. **Khởi tạo tham số đối xứng:** Sử dụng bộ sinh số ngẫu nhiên an toàn của hệ điều hành (`os.urandom`) để tạo ra một khóa phiên DES 8 byte và một vectơ khởi tạo (IV) 8 byte hoàn toàn ngẫu nhiên cho mỗi phiên truyền.
4. **Mã hóa nội dung:** Thực hiện đệm dữ liệu đầu vào theo chuẩn PKCS#7 để đưa độ dài về bội số của 8, tiến hành mã hóa ở chế độ CBC và ghép IV 8 byte vào ngay đầu khối bản mã (`iv + encrypted_body`).
5. **Mã hóa bảo vệ khóa đối xứng:** Sử dụng thuật toán bất đối xứng RSA kết hợp cơ chế đệm OAEP để mã hóa khóa phiên DES bằng khóa công khai (`receiver_public.pem`) của Người nhận.
6. **Đóng gói nhị phân mạng:** Sử dụng thư viện `struct` để chuyển độ dài các trường dữ liệu về định dạng số nguyên 4-byte dạng Big Endian, sau đó ghép nối thành một gói tin hoàn chỉnh theo giao thức định sẵn: `[len_key: 4 bytes][encrypted_des_key: N bytes][len_cipher: 4 bytes][ciphertext_with_iv: M bytes][sha256_hash: 32 bytes]`. Sau đó mở socket kết nối truyền luồng byte an toàn qua mạng.

## 3. Luồng xử lý Receiver

1. **Nhận luồng dữ liệu nhị phân:** Khởi tạo socket lắng nghe trên cổng chỉ định, chấp nhận kết nối từ Sender và sử dụng hàm đọc chính xác dòng byte (`recv_exact`) để thu thập gói tin theo đúng cấu trúc tiêu đề.
2. **Bóc tách gói tin (Parsing):** Đọc độ dài tiêu đề để tách biệt chính xác ba thành phần dữ liệu: chuỗi khóa DES đã mã hóa, chuỗi bản mã kèm IV và mã băm SHA-256 gốc.
3. **Giải mã khóa đối xứng:** Sử dụng khóa bí mật RSA cá nhân (`receiver_private.pem`) phối hợp cơ chế đệm OAEP để giải mã lấy lại khóa phiên DES 8 byte nguyên bản.
4. **Giải mã nội dung:** Tách lấy 8 byte IV ở đầu khối bản mã để thiết lập cấu hình giải mã DES-CBC, thực hiện giải mã luồng byte và loại bỏ các byte đệm PKCS#7 thừa để khôi phục plaintext gốc.
5. **Kiểm tra tính toàn vẹn:** Tính toán lại mã băm SHA-256 trên dữ liệu plaintext vừa khôi phục được.
6. **Xác thực kết quả:** So sánh chuỗi băm vừa tính toán với chuỗi băm nhận được từ gói tin. Nếu khớp nhau, hệ thống xác nhận dữ liệu hoàn toàn nguyên vẹn và ghi nhận thành công; nếu sai lệch, hệ thống lập tức cảnh báo dữ liệu đã bị can thiệp hoặc giả mạo.

## 4. Kết quả minh chứng

- **Minh chứng luồng chạy Sender:** Hệ thống khởi chạy mượt mà, ghi nhận đầy đủ tiến trình tính SHA-256, sinh khóa phiên ngẫu nhiên, mã hóa RSA-OAEP khóa DES và đẩy luồng byte qua Socket TCP thành công. Chi tiết lịch sử phiên chạy được ghi nhận đầy đủ trong tệp minh chứng thực tế: `logs/sender_success.log`.
- **Minh chứng luồng chạy Receiver:** Hệ thống lắng nghe socket chính xác, chấp nhận kết nối, bóc tách luồng tiêu đề nhị phân chuẩn định dạng mạng, giải mã RSA lấy khóa đối xứng, khôi phục plaintext rõ ràng và đối chiếu băm SHA-256 trùng khớp hoàn toàn. Chi tiết kết quả được ghi nhận đầy đủ trong tệp minh chứng thực tế: `logs/receiver_success.log`.

## 5. Nhận xét và Hướng mở rộng

- **Vai trò của các thành phần:** Việc bọc bảo vệ khóa DES bằng RSA-OAEP giúp giải quyết triệt để điểm yếu lộ khóa trên kênh truyền công khai mà không cần một kênh truyền mật phụ. Trong khi đó, SHA-256 đóng vai trò làm lá chắn bảo vệ, ngăn chặn triệt để các cuộc tấn công thay đổi nội dung tệp ở dạng mã hóa.
- **Hạn chế của DES và giải pháp nâng cấp:** Mặc dù luồng xử lý lai trong bài Lab rất chặt chẽ, thuật toán DES với kích thước khóa thực tế quá ngắn (chỉ có 56 bit hiệu lực) hiện nay đã bị coi là không còn an toàn và dễ dàng bị bẻ gãy bằng các kỹ thuật vét cạn phần cứng hiện đại. Hệ thống thực tế bắt buộc phải nâng cấp lên thuật toán **AES** (với kích thước khóa 128-bit hoặc 256-bit).
- **Tối ưu hóa bằng chế độ mã hóa nâng cao:** Thay vì áp dụng mô hình rời rạc CBC kết hợp băm rời SHA-256, hướng nâng cấp tối ưu nhất cho hệ thống thật là chuyển sang sử dụng chế độ mã hóa xác thực **AES-GCM (Galois/Counter Mode)**. Chế độ này tích hợp sẵn mã xác thực thông điệp GMAC bên trong luồng mã hóa, giúp tối ưu hóa hiệu năng tính toán, chống lại các cuộc tấn công can thiệp bản mã (Bit-flipping attacks) và bảo vệ tính toàn vẹn dữ liệu một cách toàn diện hơn mà không cần tính toán hàm băm thủ công riêng biệt.