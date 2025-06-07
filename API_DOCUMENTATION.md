# Core CA API Documentation

## Giới thiệu

Core CA API là một ứng dụng Certificate Authority (CA) cung cấp các chức năng quản lý khóa và chứng chỉ số.

## Swagger API Documentation

Sau khi khởi động ứng dụng, bạn có thể truy cập Swagger UI tại:

```
http://localhost:8080/swagger/index.html
```

## API Endpoints

### Key Management

#### 1. Generate Key Pair

- **POST** `/keymanagement/generate`
- **Mô tả**: Tạo một cặp khóa RSA mới với ID được chỉ định
- **Request Body**:

```json
{
  "id": "my-key-id"
}
```

- **Response**:

```json
{
  "id": "my-key-id"
}
```

#### 2. Get Key Pair

- **GET** `/keymanagement/{id}`
- **Mô tả**: Lấy thông tin cặp khóa theo ID và trả về public key
- **Response**:

```json
{
  "id": "my-key-id",
  "publicKey": "-----BEGIN RSA PUBLIC KEY-----\n..."
}
```

### Certificate Authority

#### 3. Issue Certificate

- **POST** `/ca/issue`
- **Mô tả**: Cấp chứng chỉ mới từ Certificate Signing Request (CSR)
- **Request Body**:

```json
{
  "csr": "-----BEGIN CERTIFICATE REQUEST-----\n..."
}
```

- **Response**: PEM encoded certificate

#### 4. Revoke Certificate

- **POST** `/ca/revoke`
- **Mô tả**: Thu hồi chứng chỉ theo serial number với lý do cụ thể
- **Request Body**:

```json
{
  "serial_number": "123456789",
  "reason": "compromised"
}
```

- **Response**:

```json
{
  "message": "Certificate revoked"
}
```

#### 5. Get Certificate Revocation List (CRL)

- **GET** `/ca/crl`
- **Mô tả**: Lấy danh sách thu hồi chứng chỉ hiện tại
- **Response**: PEM encoded CRL

## Cách chạy ứng dụng

1. Đảm bảo các dependencies đã được cài đặt:

```bash
go mod tidy
```

2. Khởi động ứng dụng:

```bash
go run main.go
```

3. Truy cập Swagger UI:

```
http://localhost:8080/swagger/index.html
```

## Error Responses

Tất cả các API endpoints đều có thể trả về error response với format:

```json
{
  "error": "Error message description"
}
```

## Lưu ý

- Ứng dụng chạy trên port 8080
- Tất cả các API endpoints đều hỗ trợ CORS
- API sử dụng JSON format cho request/response (trừ certificate và CRL endpoints)
