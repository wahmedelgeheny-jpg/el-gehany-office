CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS public.service_requests (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL CHECK (char_length(name) BETWEEN 2 AND 100),
  phone TEXT NOT NULL CHECK (phone ~ '^01[0125][0-9]{8}$'),
  service TEXT NOT NULL CHECK (service IN (
    'بطاقة الرقم القومي','جواز السفر','شهادة ميلاد','شهادة وفاة','مستندات الزواج','استفسار عام'
  )),
  details TEXT NOT NULL CHECK (char_length(details) BETWEEN 3 AND 1200),
  status TEXT NOT NULL DEFAULT 'جديد' CHECK (status IN ('جديد','قيد المتابعة','تم التواصل','مكتمل','مرفوض')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE public.service_requests ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE public.service_requests FROM anon, authenticated;
GRANT ALL ON TABLE public.service_requests TO service_role;
CREATE INDEX IF NOT EXISTS service_requests_created_at_idx ON public.service_requests (created_at DESC);
