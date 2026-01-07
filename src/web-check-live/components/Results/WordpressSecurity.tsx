import styled from '@emotion/styled';
import colors from 'web-check-live/styles/colors';
import { Card } from 'web-check-live/components/Form/Card';
import Row, { ExpandableRow } from 'web-check-live/components/Form/Row';

const cardStyles = `
  max-height: 100rem;
  overflow-y: auto;
  grid-row: span 2;
`;

const ScoreContainer = styled.div`
  display: flex;
  align-items: center;
  gap: 1rem;
  margin-bottom: 1rem;
  padding: 0.75rem;
  background: ${colors.backgroundDarker};
  border-radius: 8px;
`;

const ScoreCircle = styled.div<{ score: number }>`
  width: 60px;
  height: 60px;
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 1.25rem;
  font-weight: bold;
  background: ${props => {
    if (props.score >= 80) return colors.success;
    if (props.score >= 60) return colors.warning;
    if (props.score >= 40) return '#f39c12';
    return colors.danger;
  }};
  color: ${colors.background};
`;

const ScoreLabel = styled.div`
  flex: 1;
  span {
    display: block;
    font-size: 0.85rem;
    color: ${colors.textColorSecondary};
  }
  strong {
    color: ${colors.textColor};
  }
`;

const Section = styled.details`
  margin: 0.5rem 0;
  border: 1px solid ${colors.primaryTransparent};
  border-radius: 4px;
  padding: 0.5rem;

  summary {
    cursor: pointer;
    font-weight: bold;
    padding: 0.25rem;
    color: ${colors.textColor};

    &::marker {
      color: ${colors.primary};
    }
  }

  &[open] {
    background: ${colors.backgroundDarker};
  }
`;

const SeverityBadge = styled.span<{ severity: string }>`
  display: inline-block;
  padding: 0.15rem 0.5rem;
  border-radius: 4px;
  font-size: 0.75rem;
  font-weight: bold;
  margin-right: 0.5rem;
  background: ${props => {
    switch (props.severity) {
      case 'critical': return '#dc3545';
      case 'high': return '#fd7e14';
      case 'medium': return '#ffc107';
      case 'low': return '#17a2b8';
      default: return colors.primary;
    }
  }};
  color: ${props => props.severity === 'medium' ? '#000' : '#fff'};
`;

const RecommendationItem = styled.div`
  padding: 0.5rem;
  margin: 0.5rem 0;
  border-left: 3px solid ${colors.primary};
  background: ${colors.backgroundDarker};
  border-radius: 0 4px 4px 0;

  .title {
    font-weight: bold;
    color: ${colors.textColor};
  }

  .description {
    font-size: 0.85rem;
    color: ${colors.textColorSecondary};
    margin-top: 0.25rem;
  }
`;

const PluginList = styled.div`
  .plugin-item {
    padding: 0.25rem 0;
    border-bottom: 1px solid ${colors.primaryTransparent};

    &:last-child {
      border-bottom: none;
    }
  }

  .plugin-name {
    font-weight: 500;
  }

  .plugin-version {
    color: ${colors.textColorSecondary};
    font-size: 0.85rem;
  }

  .vuln-warning {
    color: ${colors.danger};
    font-size: 0.8rem;
  }
`;

const WordpressSecurityCard = (props: { data: any, title: string, actionButtons: any }): JSX.Element => {
  const data = props.data;

  // Handle non-WordPress sites
  if (!data.isWordPress) {
    return (
      <Card heading={props.title} actionButtons={props.actionButtons}>
        <Row lbl="WordPress Detected" val="❌ No" />
        <Row lbl="Status" val={data.skipped || 'Not a WordPress site'} />
      </Card>
    );
  }

  const {
    version,
    theme,
    plugins = [],
    exposedFiles = [],
    xmlRpc,
    userEnumeration,
    directoryListing = [],
    restApi,
    securityScore = 0,
    recommendations = [],
  } = data;

  const criticalCount = recommendations.filter((r: any) => r.severity === 'critical').length;
  const highCount = recommendations.filter((r: any) => r.severity === 'high').length;
  const mediumCount = recommendations.filter((r: any) => r.severity === 'medium').length;
  const lowCount = recommendations.filter((r: any) => r.severity === 'low').length;

  const vulnPlugins = plugins.filter((p: any) => p.vulnerabilities?.length > 0);

  return (
    <Card heading={props.title} styles={cardStyles} actionButtons={props.actionButtons}>
      {/* Security Score */}
      <ScoreContainer>
        <ScoreCircle score={securityScore}>{securityScore}</ScoreCircle>
        <ScoreLabel>
          <strong>Security Score</strong>
          <span>
            {criticalCount > 0 && `${criticalCount} Critical `}
            {highCount > 0 && `${highCount} High `}
            {mediumCount > 0 && `${mediumCount} Medium `}
            {lowCount > 0 && `${lowCount} Low`}
            {criticalCount + highCount + mediumCount + lowCount === 0 && 'No issues found'}
          </span>
        </ScoreLabel>
      </ScoreContainer>

      {/* Basic Info */}
      <Row lbl="WordPress Detected" val="✅ Yes" />
      <Row lbl="Version" val={version?.detected || 'Unknown'} />
      {version?.vulnerabilities?.length > 0 && (
        <Row lbl="Core Vulnerabilities" val={`❌ ${version.vulnerabilities.length} known CVE(s)`} />
      )}

      {/* Version Section */}
      <Section>
        <summary>Version & Core ({version?.detected || 'Unknown'})</summary>
        <Row lbl="Detected Version" val={version?.detected || 'Could not detect'} />
        <Row lbl="Detection Source" val={version?.source || 'N/A'} />
        {version?.vulnerabilities?.map((vuln: any, i: number) => (
          <Row key={i} lbl={vuln.id} val={`${vuln.severity.toUpperCase()}: ${vuln.description}`} />
        ))}
        {(!version?.vulnerabilities || version.vulnerabilities.length === 0) && (
          <Row lbl="Known Vulnerabilities" val="✅ None detected" />
        )}
      </Section>

      {/* Theme Section */}
      {theme && (
        <Section>
          <summary>Theme ({theme.name || theme.slug})</summary>
          <Row lbl="Theme Name" val={theme.name || theme.slug} />
          <Row lbl="Version" val={theme.version || 'Unknown'} />
        </Section>
      )}

      {/* Plugins Section */}
      <Section>
        <summary>Plugins ({plugins.length} detected, {vulnPlugins.length} vulnerable)</summary>
        {plugins.length === 0 ? (
          <Row lbl="Plugins" val="No plugins detected" />
        ) : (
          <PluginList>
            {plugins.map((plugin: any, i: number) => (
              <div key={i} className="plugin-item">
                <span className="plugin-name">{plugin.name || plugin.slug}</span>
                <span className="plugin-version"> v{plugin.version || '?'}</span>
                {plugin.vulnerabilities?.length > 0 && (
                  <div className="vuln-warning">
                    ⚠️ {plugin.vulnerabilities.map((v: any) => v.id).join(', ')}
                  </div>
                )}
              </div>
            ))}
          </PluginList>
        )}
      </Section>

      {/* Exposed Files Section */}
      <Section>
        <summary>Sensitive Files ({exposedFiles.length} exposed)</summary>
        <Row lbl="wp-config.php" val={exposedFiles.find((f: any) => f.name === 'wp-config.php') ? '❌ Exposed!' : '✅ Protected'} />
        <Row lbl="wp-config Backups" val={exposedFiles.find((f: any) => f.name.includes('.bak') || f.name.includes('~')) ? '❌ Exposed!' : '✅ Protected'} />
        <Row lbl="debug.log" val={exposedFiles.find((f: any) => f.name === 'debug.log') ? '❌ Exposed!' : '✅ Protected'} />
        <Row lbl="readme.html" val={exposedFiles.find((f: any) => f.name === 'readme.html') ? '⚠️ Visible' : '✅ Hidden'} />
        {exposedFiles.filter((f: any) => f.critical).length > 0 && (
          <Row lbl="Critical Files Exposed" val={exposedFiles.filter((f: any) => f.critical).map((f: any) => f.name).join(', ')} />
        )}
      </Section>

      {/* XML-RPC Section */}
      <Section>
        <summary>XML-RPC ({xmlRpc?.enabled ? '❌ Enabled' : '✅ Disabled'})</summary>
        <Row lbl="XML-RPC Status" val={xmlRpc?.enabled ? '❌ Enabled' : '✅ Disabled'} />
        {xmlRpc?.enabled && (
          <>
            <Row lbl="Pingback Enabled" val={xmlRpc.pingbackEnabled ? '❌ Yes (DDoS risk)' : '✅ No'} />
            <Row lbl="Methods Available" val={xmlRpc.totalMethods || xmlRpc.methods?.length || 0} />
          </>
        )}
      </Section>

      {/* User Enumeration Section */}
      <Section>
        <summary>User Enumeration ({userEnumeration?.restApiExposed ? '❌ Vulnerable' : '✅ Protected'})</summary>
        <Row lbl="REST API Users" val={userEnumeration?.restApiExposed ? '❌ Exposed' : '✅ Protected'} />
        <Row lbl="Author Archives" val={userEnumeration?.authorArchivesEnabled ? '⚠️ Enabled' : '✅ Disabled'} />
        {userEnumeration?.usersFound?.length > 0 && (
          <Row lbl="Users Found" val={userEnumeration.usersFound.map((u: any) => u.name || u.slug).join(', ')} />
        )}
      </Section>

      {/* Directory Listing Section */}
      <Section>
        <summary>Directory Listing ({directoryListing.length > 0 ? '❌ Exposed' : '✅ Protected'})</summary>
        <Row lbl="/wp-content/uploads/" val={directoryListing.includes('/wp-content/uploads/') ? '❌ Listed' : '✅ Protected'} />
        <Row lbl="/wp-content/plugins/" val={directoryListing.includes('/wp-content/plugins/') ? '❌ Listed' : '✅ Protected'} />
        <Row lbl="/wp-includes/" val={directoryListing.includes('/wp-includes/') ? '❌ Listed' : '✅ Protected'} />
      </Section>

      {/* REST API Section */}
      <Section>
        <summary>REST API ({restApi?.exposed ? '⚠️ Exposed' : '✅ Restricted'})</summary>
        <Row lbl="API Accessible" val={restApi?.exposed ? '⚠️ Yes' : '✅ No'} />
        {restApi?.namespaces?.length > 0 && (
          <Row lbl="Namespaces" val={restApi.namespaces.slice(0, 5).join(', ')} />
        )}
      </Section>

      {/* Recommendations Section */}
      {recommendations.length > 0 && (
        <Section open>
          <summary>Recommendations ({recommendations.length})</summary>
          {recommendations.slice(0, 10).map((rec: any, i: number) => (
            <RecommendationItem key={i}>
              <SeverityBadge severity={rec.severity}>{rec.severity.toUpperCase()}</SeverityBadge>
              <span className="title">{rec.title}</span>
              <div className="description">{rec.description}</div>
            </RecommendationItem>
          ))}
        </Section>
      )}
    </Card>
  );
};

export default WordpressSecurityCard;
