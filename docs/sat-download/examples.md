# SAT Web Service examples

These examples are educational templates for request shape and transport. They are not complete signed payloads.

## Safety note

Do not paste real e.firma material, tokens, or taxpayer XML into examples, issues, tests, or documentation.

## Authentication transport

```bash
curl -X POST \
  'https://cfdidescargamasivasolicitud.clouda.sat.gob.mx/Autenticacion/Autenticacion.svc' \
  -H 'Content-Type: text/xml; charset=utf-8' \
  --data-binary @autentica-signed.xml
```

The difficult part is not `curl`; it is building the WS-Security signed XML correctly.

## Classic official request transport

```bash
curl -X POST \
  'https://cfdidescargamasivasolicitud.clouda.sat.gob.mx/SolicitaDescargaService.svc' \
  -H 'Content-Type: text/xml; charset=utf-8' \
  -H 'SOAPAction: "http://DescargaMasivaTerceros.sat.gob.mx/ISolicitaDescargaService/SolicitaDescarga"' \
  -H 'Authorization: WRAP access_token="TOKEN_VIGENTE"' \
  --data-binary @solicita-signed.xml
```

## Verification transport

```bash
curl -X POST \
  'https://cfdidescargamasivasolicitud.clouda.sat.gob.mx/VerificaSolicitudDescargaService.svc' \
  -H 'Content-Type: text/xml; charset=utf-8' \
  -H 'SOAPAction: "http://DescargaMasivaTerceros.sat.gob.mx/IVerificaSolicitudDescargaService/VerificaSolicitudDescarga"' \
  -H 'Authorization: WRAP access_token="TOKEN_VIGENTE"' \
  --data-binary @verifica-signed.xml
```

## Download transport

```bash
curl -X POST \
  'https://cfdidescargamasiva.clouda.sat.gob.mx/DescargaMasivaService.svc' \
  -H 'Content-Type: text/xml; charset=utf-8' \
  -H 'SOAPAction: "http://DescargaMasivaTerceros.sat.gob.mx/IDescargaMasivaTercerosService/Descargar"' \
  -H 'Authorization: WRAP access_token="TOKEN_VIGENTE"' \
  --data-binary @descarga-signed.xml
```

## Unsigned request shape

```xml
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
  <s:Header/>
  <s:Body>
    <SolicitaDescarga xmlns="http://DescargaMasivaTerceros.sat.gob.mx">
      <solicitud
        FechaInicial="2026-01-01T00:00:00"
        FechaFinal="2026-01-31T23:59:59"
        RfcEmisor="AAA010101AAA"
        RfcSolicitante="AAA010101AAA"
        TipoSolicitud="Metadata"
        EstadoComprobante="1">
        <RfcReceptores>
          <RfcReceptor>BBB010101BBB</RfcReceptor>
        </RfcReceptores>
        <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
          <!-- XMLDSig content goes here -->
        </Signature>
      </solicitud>
    </SolicitaDescarga>
  </s:Body>
</s:Envelope>
```

## Expected response shapes

### Request accepted

```xml
<SolicitaDescargaResult
  IdSolicitud="00000000-0000-0000-0000-000000000000"
  CodEstatus="5000"
  Mensaje="Solicitud Aceptada" />
```

### Verification finished

```xml
<VerificaSolicitudDescargaResult
  CodEstatus="5000"
  EstadoSolicitud="3"
  CodigoEstadoSolicitud="5000"
  NumeroCFDIs="10"
  Mensaje="Solicitud Aceptada">
  <IdsPaquetes>00000000-0000-0000-0000-000000000000_01</IdsPaquetes>
</VerificaSolicitudDescargaResult>
```

### Package download

```xml
<RespuestaDescargaMasivaTercerosSalida>
  <Paquete>UEsDB...</Paquete>
</RespuestaDescargaMasivaTercerosSalida>
```

The application must base64-decode `Paquete`, persist the ZIP bytes, hash them, and only then extract XML or TXT content.
