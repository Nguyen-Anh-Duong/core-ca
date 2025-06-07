#!/bin/bash

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                  Core CA API - Swagger Demo                  ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

echo -e "${YELLOW}🎉 Swagger API đã được thiết lập thành công!${NC}"
echo ""

echo -e "${GREEN}📋 Tính năng đã được triển khai:${NC}"
echo "  ✅ Swagger UI Documentation"
echo "  ✅ 5 API endpoints với đầy đủ annotations"
echo "  ✅ Request/Response models"
echo "  ✅ Error handling"
echo "  ✅ API documentation file"
echo "  ✅ Test script và Makefile"
echo ""

echo -e "${GREEN}🔧 API Endpoints:${NC}"
echo "  📝 POST /keymanagement/generate    - Tạo cặp khóa mới"
echo "  🔍 GET  /keymanagement/{id}        - Lấy thông tin khóa"
echo "  📄 POST /ca/issue                  - Cấp chứng chỉ mới"
echo "  ❌ POST /ca/revoke                 - Thu hồi chứng chỉ"
echo "  📜 GET  /ca/crl                    - Lấy danh sách thu hồi"
echo ""

echo -e "${GREEN}🚀 Cách sử dụng:${NC}"
echo ""
echo -e "${YELLOW}1. Khởi động server:${NC}"
echo "   make run"
echo "   # hoặc: go run main.go"
echo ""

echo -e "${YELLOW}2. Truy cập Swagger UI:${NC}"
echo "   http://localhost:8080/swagger/index.html"
echo ""

echo -e "${YELLOW}3. Test API endpoints:${NC}"
echo "   make test-api"
echo "   # hoặc: ./test_api.sh"
echo ""

echo -e "${YELLOW}4. Regenerate docs (nếu cần):${NC}"
echo "   make swagger"
echo ""

echo -e "${GREEN}📁 Files đã tạo:${NC}"
echo "  📄 main.go - Updated với Swagger annotations"
echo "  📁 docs/ - Swagger documentation files"
echo "  📋 API_DOCUMENTATION.md - Hướng dẫn API"
echo "  🧪 test_api.sh - Script test API"
echo "  ⚙️  Makefile - Build và management commands"
echo ""

echo -e "${BLUE}💡 Lưu ý:${NC}"
echo "  • Server chạy trên port 8080"
echo "  • Swagger UI tự động reload khi có thay đổi"
echo "  • Tất cả endpoints đều có validation và error handling"
echo "  • API documentation tự động sync với code"
echo ""

echo -e "${GREEN}🎯 Sẵn sàng sử dụng! Hãy chạy 'make run' để bắt đầu.${NC}" 