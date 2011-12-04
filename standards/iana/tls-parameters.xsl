<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet 
  xmlns="http://www.w3.org/1999/xhtml"
  xmlns:iana="http://www.iana.org/assignments"
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">

  <xsl:import href="iana-registry.xsl" />

  <xsl:template name="iana:record_header">
    <xsl:choose> 
      <xsl:when test="@id = 'tls-parameters-1' or
                      @id = 'tls-parameters-11' or
                      @id = 'tls-parameters-13' or
                      @id = 'tls-parameters-15' or
                      @id = 'tls-parameters-17' or
                      @id = 'authorization-data-rules'">
        <tr><th>Range</th><th>Registration Procedures</th></tr>
      </xsl:when>
      <xsl:when test="@id = 'tls-parameters-2' or
                      @id = 'tls-parameters-4' or
                      @id = 'tls-parameters-5' or
                      @id = 'tls-parameters-6' or
                      @id = 'tls-parameters-7' or
                      @id = 'tls-parameters-8' or
                      @id = 'tls-parameters-9' or
                      @id = 'tls-parameters-10' or
                      @id = 'tls-parameters-12' or
                      @id = 'tls-parameters-14' or
                      @id = 'tls-parameters-16' or
                      @id = 'tls-parameters-18' or
                      @id = 'authorization-data'">
        <tr><th>Value</th><th>Description</th><th>DTLS-OK</th><th>Reference</th></tr>
      </xsl:when>
      <xsl:when test="@id = 'tls-parameters-3'">
        <tr><th>Range</th><th>Registration Procedures</th><th>Notes</th></tr>
      </xsl:when>
      <xsl:when test="@id = 'exporter-labels'">
        <tr><th>Value</th><th>DTLS-OK</th><th>Reference</th><th>Note</th></tr>
      </xsl:when>
    </xsl:choose>
  </xsl:template>

  <xsl:template match="iana:record">
    <xsl:choose>
      <xsl:when test="../@id = 'tls-parameters-1' or
                      ../@id = 'tls-parameters-11' or
                      ../@id = 'tls-parameters-13' or
                      ../@id = 'tls-parameters-15' or
                      ../@id = 'tls-parameters-17' or
                      ../@id = 'authorization-data-rules'">
        <tr>
          <td align="center"><xsl:value-of select="iana:value"/></td>
          <td><xsl:value-of select="iana:registration_rule"/></td>
        </tr>
      </xsl:when>
      <xsl:when test="../@id = 'tls-parameters-2' or
                      ../@id = 'tls-parameters-5' or
                      ../@id = 'tls-parameters-6' or
                      ../@id = 'tls-parameters-7' or
                      ../@id = 'tls-parameters-8' or
                      ../@id = 'tls-parameters-9' or
                      ../@id = 'tls-parameters-10' or
                      ../@id = 'tls-parameters-12' or
                      ../@id = 'tls-parameters-14' or
                      ../@id = 'tls-parameters-16' or
                      ../@id = 'tls-parameters-18' or
                      ../@id = 'authorization-data'">
        <tr>
          <td align="center"><xsl:value-of select="iana:value"/></td>
          <td><xsl:value-of select="iana:description"/></td>
          <td><xsl:value-of select="iana:dtls"/></td>
          <td><xsl:apply-templates select="iana:xref"/></td>
        </tr>
      </xsl:when>
      <xsl:when test="../@id = 'tls-parameters-3'">
        <tr>
          <td align="center"><xsl:value-of select="iana:value"/></td>
          <td><xsl:value-of select="iana:registration_rule"/></td>
          <td><xsl:value-of select="iana:note"/></td>
        </tr>
      </xsl:when>
      <xsl:when test="../@id = 'exporter-labels'">
        <tr>
          <td><xsl:value-of select="iana:description"/></td>
          <td><xsl:value-of select="iana:dtls"/></td>
          <td><xsl:apply-templates select="iana:xref"/></td>
          <td><xsl:value-of select="iana:note"/></td>
        </tr>
      </xsl:when>
      <xsl:when test="../@id = 'tls-parameters-4'">
        <tr>
          <td align="center" style="font-family:monospace"><xsl:value-of select="iana:value"/></td>
          <td><xsl:value-of select="iana:description"/></td>
          <td><xsl:value-of select="iana:dtls"/></td>
          <td><xsl:apply-templates select="iana:xref"/></td>
        </tr>
      </xsl:when>
    </xsl:choose>
  </xsl:template>

</xsl:stylesheet>
