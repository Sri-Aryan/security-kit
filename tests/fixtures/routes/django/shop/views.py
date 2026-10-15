from rest_framework import viewsets
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny

def about(request):
    return None

class OpenView(APIView):
    permission_classes = [AllowAny]
    def get(self, request):
        return None

class OrderViewSet(viewsets.ModelViewSet):
    queryset = None
