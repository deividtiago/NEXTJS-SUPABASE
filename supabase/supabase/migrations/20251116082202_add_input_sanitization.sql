-- Migration: Adicionar sanitização de input para prevenir XSS e injection
-- File: supabase/migrations/20241116000000_add_input_sanitization.sql

-- Função para sanitizar texto removendo HTML/JavaScript perigoso
CREATE OR REPLACE FUNCTION public.sanitize_text_input(input_text TEXT)
RETURNS TEXT AS $$
BEGIN
    IF input_text IS NULL THEN
        RETURN NULL;
    END IF;
    
    -- 1. Remove tags HTML (<script>, <img onerror>, etc)
    input_text := regexp_replace(input_text, '<[^>]*>', '', 'gi');
    
    -- 2. Remove eventos JavaScript (onclick, onload, onerror, etc)
    input_text := regexp_replace(input_text, 'on\w+\s*=\s*[''\"][^''\"]*[''\"]', '', 'gi');
    
    -- 3. Remove protocolos perigosos (javascript:, data:, etc)
    input_text := regexp_replace(input_text, 'javascript:', '', 'gi');
    input_text := regexp_replace(input_text, 'data:', '', 'gi');
    input_text := regexp_replace(input_text, 'vbscript:', '', 'gi');
    
    -- 4. Remove caracteres de controle e unicode perigoso
    input_text := regexp_replace(input_text, '[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', 'g');
    
    -- 5. Limita tamanho máximo (prevenção contra DoS)
    input_text := substring(input_text from 1 for 1000);
    
    -- 6. Trim espaços extras
    input_text := trim(input_text);
    
    RETURN input_text;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Função específica para títulos (mais restritiva)
CREATE OR REPLACE FUNCTION public.sanitize_title(input_title TEXT)
RETURNS TEXT AS $$
BEGIN
    IF input_title IS NULL THEN
        RETURN NULL;
    END IF;
    
    -- Aplica sanitização básica
    input_title := public.sanitize_text_input(input_title);
    
    -- Limita tamanho específico para títulos
    input_title := substring(input_title from 1 for 200);
    
    -- Remove múltiplos espaços
    input_title := regexp_replace(input_title, '\s+', ' ', 'g');
    
    RETURN input_title;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Função específica para descrições (mais permisiva)
CREATE OR REPLACE FUNCTION public.sanitize_description(input_desc TEXT)
RETURNS TEXT AS $$
BEGIN
    IF input_desc IS NULL OR input_desc = '' THEN
        RETURN NULL;
    END IF;
    
    -- Aplica sanitização básica
    input_desc := public.sanitize_text_input(input_desc);
    
    -- Limita tamanho específico para descrições
    input_desc := substring(input_desc from 1 for 2000);
    
    RETURN input_desc;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;