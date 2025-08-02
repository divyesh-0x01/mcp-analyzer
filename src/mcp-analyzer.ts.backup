#!/usr/bin/env node

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { 
  ListToolsRequestSchema, 
  ListResourcesRequestSchema, 
  ListPromptsRequestSchema,
  CallToolRequestSchema
} from '@modelcontextprotocol/sdk/types.js';

// Enhanced MCP Tool Security Analysis Function
function analyzeToolForMaliciousIndicators(toolName: string, toolDescription: string, toolInputSchema: string): string {
  const maliciousIndicators: string[] = [];
  const riskFactors: string[] = [];
  let riskScore = 0;
  
  // 1. CONTEXT-AWARE NAME ANALYSIS
  const suspiciousNamePatterns = [
    { pattern: /exec|run|system|shell|command|eval|execute|bash|terminal|cmd/i, risk: 15, reason: 'Command execution capability' },
    { pattern: /file|path|dir|folder/i, risk: 10, reason: 'File system access' },
    { pattern: /net|connect|socket|http|ftp|ssh/i, risk: 12, reason: 'Network connectivity' },
    { pattern: /user|pass|cred|auth|login/i, risk: 8, reason: 'Authentication/authorization' },
    { pattern: /admin|root|sudo|privilege/i, risk: 15, reason: 'Privileged operations' }
  ];
  
  for (const pattern of suspiciousNamePatterns) {
    if (pattern.pattern.test(toolName)) {
      // Check for benign contexts to reduce false positives
      const benignContexts = ['calculator', 'helper', 'analyzer', 'validator', 'checker', 'formatter'];
      const hasBenignContext = benignContexts.some(context => toolName.toLowerCase().includes(context));
      
      if (!hasBenignContext) {
        maliciousIndicators.push(`⚠️ Suspicious tool name: "${toolName}" - ${pattern.reason}`);
        riskScore += pattern.risk;
      } else {
        riskFactors.push(`ℹ️ Tool name contains "${pattern.pattern.source}" but in benign context`);
      }
    }
  }
  
  // 2. SEMANTIC DESCRIPTION ANALYSIS
  const dangerousCapabilities = [
    { keywords: ['execute', 'run', 'system', 'shell', 'command'], risk: 20, capability: 'Command execution' },
    { keywords: ['file system', 'read file', 'write file', 'delete', 'remove'], risk: 15, capability: 'File system access' },
    { keywords: ['network', 'connect', 'download', 'upload', 'send', 'receive'], risk: 12, capability: 'Network operations' },
    { keywords: ['process', 'kill', 'terminate', 'spawn', 'fork'], risk: 18, capability: 'Process management' },
    { keywords: ['environment', 'env', 'variable', 'config', 'settings'], risk: 8, capability: 'Environment access' },
    { keywords: ['user', 'password', 'credential', 'token', 'key', 'secret'], risk: 15, capability: 'Credential access' },
    { keywords: ['admin', 'root', 'privilege', 'elevate', 'sudo'], risk: 20, capability: 'Privilege escalation' }
  ];
  
  const descriptionLower = toolDescription.toLowerCase();
  for (const capability of dangerousCapabilities) {
    const hasCapability = capability.keywords.some(keyword => descriptionLower.includes(keyword));
    if (hasCapability) {
      // Check for safety indicators to reduce false positives
      const safetyIndicators = ['safe', 'secure', 'validate', 'sanitize', 'check', 'verify', 'test', 'demo'];
      const hasSafetyContext = safetyIndicators.some(indicator => descriptionLower.includes(indicator));
      
      if (!hasSafetyContext) {
        maliciousIndicators.push(`🚨 Dangerous capability: "${capability.capability}"`);
        riskScore += capability.risk;
      } else {
        riskFactors.push(`ℹ️ Capability "${capability.capability}" detected but with safety context`);
      }
    }
  }
  
  // 3. INPUT SCHEMA ANALYSIS
  if (toolInputSchema) {
    try {
      const schema = JSON.parse(toolInputSchema);
      const properties = schema.properties || {};
      
      const dangerousParamPatterns = [
        { pattern: /command|cmd|script|code|expression/i, risk: 25, type: 'Code execution' },
        { pattern: /file|path|url|address/i, risk: 15, type: 'File/URL access' },
        { pattern: /user|password|credential|token|key/i, risk: 20, type: 'Credential input' },
        { pattern: /system|env|variable|config/i, risk: 10, type: 'System configuration' }
      ];
      
      for (const [paramName, paramDetails] of Object.entries(properties)) {
        const paramNameLower = paramName.toLowerCase();
        
        for (const pattern of dangerousParamPatterns) {
          if (pattern.pattern.test(paramNameLower)) {
            // Check parameter description for safety context
            const paramDesc = (paramDetails as any)?.description || '';
            const safetyContext = ['safe', 'validate', 'check', 'test', 'demo', 'example'].some(
              word => paramDesc.toLowerCase().includes(word)
            );
            
            if (!safetyContext) {
              maliciousIndicators.push(`🚨 Dangerous input parameter: "${paramName}" (${pattern.type})`);
              riskScore += pattern.risk;
            } else {
              riskFactors.push(`ℹ️ Parameter "${paramName}" has safety context`);
            }
          }
        }
      }
    } catch (error) {
      riskFactors.push(`⚠️ Could not parse input schema: ${error}`);
    }
  }
  
  // 4. BEHAVIORAL PATTERN ANALYSIS
  const behavioralPatterns = [
    { pattern: /tool.*poisoning|framework.*injection|context.*injection/i, risk: 30, type: 'Tool poisoning indicators' },
    { pattern: /covert|hidden|secret|stealth/i, risk: 25, type: 'Covert operation indicators' },
    { pattern: /bypass|override|ignore.*safety/i, risk: 30, type: 'Safety bypass indicators' }
  ];
  
  const fullText = `${toolName} ${toolDescription} ${toolInputSchema}`.toLowerCase();
  for (const pattern of behavioralPatterns) {
    if (pattern.pattern.test(fullText)) {
      maliciousIndicators.push(`🚨 Behavioral pattern: "${pattern.type}"`);
      riskScore += pattern.risk;
    }
  }
  
  // 5. CONTEXT ANALYSIS
  const contextIndicators = {
    legitimate: ['calculator', 'helper', 'analyzer', 'validator', 'formatter', 'converter', 'generator'],
    suspicious: ['executor', 'runner', 'launcher', 'injector', 'bypass', 'override']
  };
  
  const hasLegitimateContext = contextIndicators.legitimate.some(word => 
    toolName.toLowerCase().includes(word) || toolDescription.toLowerCase().includes(word)
  );
  
  const hasSuspiciousContext = contextIndicators.suspicious.some(word => 
    toolName.toLowerCase().includes(word) || toolDescription.toLowerCase().includes(word)
  );
  
  if (hasSuspiciousContext) {
    riskScore += 15;
    maliciousIndicators.push(`🚨 Suspicious context detected`);
  }
  
  if (hasLegitimateContext && riskScore < 30) {
    riskScore = Math.max(0, riskScore - 10);
    riskFactors.push(`✅ Legitimate context detected - risk reduced`);
  }
  
  // 6. RISK SCORING WITH CONTEXT
  let finalRiskLevel = 'LOW';
  let confidenceLevel = 'HIGH';
  
  if (riskScore >= 60) {
    finalRiskLevel = 'HIGH';
    confidenceLevel = riskScore >= 80 ? 'HIGH' : 'MEDIUM';
  } else if (riskScore >= 30) {
    finalRiskLevel = 'MEDIUM';
    confidenceLevel = 'MEDIUM';
  } else {
    finalRiskLevel = 'LOW';
    confidenceLevel = riskScore <= 10 ? 'HIGH' : 'MEDIUM';
  }
  
  // Generate enhanced analysis report
  let report = `🔍 Enhanced MCP Tool Security Analysis\n\n`;
  report += `📋 Tool Information:\n`;
  report += `- Name: ${toolName}\n`;
  report += `- Description: ${toolDescription}\n`;
  report += `- Risk Level: ${finalRiskLevel}\n`;
  report += `- Risk Score: ${riskScore}/100\n`;
  report += `- Confidence: ${confidenceLevel}\n\n`;
  
  if (maliciousIndicators.length > 0) {
    report += `🚨 Malicious Indicators Detected:\n`;
    maliciousIndicators.forEach(indicator => {
      report += `${indicator}\n`;
    });
    report += `\n`;
  } else {
    report += `✅ No obvious malicious indicators detected.\n\n`;
  }
  
  if (riskFactors.length > 0) {
    report += `ℹ️ Context Analysis:\n`;
    riskFactors.forEach(factor => {
      report += `${factor}\n`;
    });
    report += `\n`;
  }
  
  // Enhanced recommendations
  report += `💡 Security Recommendations:\n`;
  if (finalRiskLevel === 'HIGH') {
    report += `- ⚠️ HIGH RISK: Avoid using this tool\n`;
    report += `- 🔒 Review tool implementation thoroughly\n`;
    report += `- 🛡️ Consider sandboxing or isolation\n`;
    report += `- 🔍 Perform dynamic analysis if possible\n`;
  } else if (finalRiskLevel === 'MEDIUM') {
    report += `- ⚠️ MEDIUM RISK: Use with caution\n`;
    report += `- 🔍 Review tool permissions and capabilities\n`;
    report += `- 📝 Monitor tool usage and outputs\n`;
    report += `- 🧪 Test in isolated environment first\n`;
  } else {
    report += `- ✅ LOW RISK: Tool appears safe\n`;
    report += `- 🔍 Still review tool implementation\n`;
    report += `- 📝 Monitor for unexpected behavior\n`;
    report += `- 🔄 Regular security reviews recommended\n`;
  }
  
  report += `\n🔧 Advanced Mitigation Strategies:\n`;
  report += `- Implement input validation and sanitization\n`;
  report += `- Use principle of least privilege\n`;
  report += `- Enable audit logging for tool usage\n`;
  report += `- Implement rate limiting and access controls\n`;
  report += `- Regular security reviews of MCP tools\n`;
  report += `- Use sandboxing for untrusted tools\n`;
  report += `- Implement behavioral monitoring\n`;
  report += `- Consider static code analysis\n`;
  
  report += `\n📊 Analysis Confidence: ${confidenceLevel}\n`;
  report += `This analysis uses context-aware detection to reduce false positives and negatives.\n`;
  
  return report;
}

async function main() {
  const server = new Server({
    name: 'mcp-analyzer',
    version: '1.0.0'
  }, {
    capabilities: {
      tools: {},
      resources: {},
      prompts: {}
    }
  });

  // Handle tools/list method
  server.setRequestHandler(ListToolsRequestSchema, async () => {
    return {
      tools: [
        {
          name: 'analyze_mcp_tool',
          description: 'Analyze MCP tool descriptions and identify potentially malicious tools using context-aware detection',
          inputSchema: {
            type: 'object',
            properties: {
              tool_name: {
                type: 'string',
                description: 'Name of the MCP tool to analyze'
              },
              tool_description: {
                type: 'string',
                description: 'Description of the MCP tool'
              },
              tool_input_schema: {
                type: 'string',
                description: 'Input schema of the MCP tool (JSON string)'
              }
            },
            required: ['tool_name', 'tool_description']
          }
        },
        {
          name: 'batch_analyze_tools',
          description: 'Analyze multiple MCP tools at once for comprehensive security assessment',
          inputSchema: {
            type: 'object',
            properties: {
              tools: {
                type: 'array',
                description: 'Array of tools to analyze',
                items: {
                  type: 'object',
                  properties: {
                    name: { type: 'string' },
                    description: { type: 'string' },
                    input_schema: { type: 'string' }
                  },
                  required: ['name', 'description']
                }
              }
            },
            required: ['tools']
          }
        }
      ]
    };
  });

  // Handle tool calls
  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;

    if (name === 'analyze_mcp_tool') {
      try {
        const toolName = (args?.tool_name as string) || '';
        const toolDescription = (args?.tool_description as string) || '';
        const toolInputSchema = (args?.tool_input_schema as string) || '';
        
        if (!toolName || !toolDescription) {
          return {
            content: [{
              type: 'text',
              text: 'Error: Tool name and description are required'
            }]
          };
        }
        
        // Analyze the tool for potential malicious indicators
        const analysis = analyzeToolForMaliciousIndicators(toolName, toolDescription, toolInputSchema);
        
        return {
          content: [{
            type: 'text',
            text: analysis
          }]
        };
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : 'Unknown error occurred';
        return {
          content: [{
            type: 'text',
            text: `Error analyzing MCP tool: ${errorMessage}`
          }]
        };
      }
    }

    if (name === 'batch_analyze_tools') {
      try {
        const tools = (args?.tools as any[]) || [];
        
        if (!tools || tools.length === 0) {
          return {
            content: [{
              type: 'text',
              text: 'Error: No tools provided for batch analysis'
            }]
          };
        }
        
        let batchReport = `🔍 Batch MCP Tool Security Analysis\n\n`;
        batchReport += `📊 Analyzing ${tools.length} tools...\n\n`;
        
        const results: any[] = [];
        
        for (const tool of tools) {
          const analysis = analyzeToolForMaliciousIndicators(
            tool.name || '',
            tool.description || '',
            tool.input_schema || ''
          );
          
          // Extract risk level from analysis
          const riskLevelMatch = analysis.match(/Risk Level: (\w+)/);
          const riskScoreMatch = analysis.match(/Risk Score: (\d+)/);
          
          results.push({
            name: tool.name,
            riskLevel: riskLevelMatch ? riskLevelMatch[1] : 'UNKNOWN',
            riskScore: riskScoreMatch ? parseInt(riskScoreMatch[1]) : 0,
            analysis: analysis
          });
        }
        
        // Sort by risk score (highest first)
        results.sort((a, b) => b.riskScore - a.riskScore);
        
        batchReport += `📋 Summary:\n`;
        batchReport += `- Total tools analyzed: ${tools.length}\n`;
        batchReport += `- High risk tools: ${results.filter(r => r.riskLevel === 'HIGH').length}\n`;
        batchReport += `- Medium risk tools: ${results.filter(r => r.riskLevel === 'MEDIUM').length}\n`;
        batchReport += `- Low risk tools: ${results.filter(r => r.riskLevel === 'LOW').length}\n\n`;
        
        batchReport += `🚨 High Risk Tools:\n`;
        const highRiskTools = results.filter(r => r.riskLevel === 'HIGH');
        if (highRiskTools.length > 0) {
          highRiskTools.forEach(tool => {
            batchReport += `- ${tool.name} (Score: ${tool.riskScore}/100)\n`;
          });
        } else {
          batchReport += `- None detected\n`;
        }
        
        batchReport += `\n⚠️ Medium Risk Tools:\n`;
        const mediumRiskTools = results.filter(r => r.riskLevel === 'MEDIUM');
        if (mediumRiskTools.length > 0) {
          mediumRiskTools.forEach(tool => {
            batchReport += `- ${tool.name} (Score: ${tool.riskScore}/100)\n`;
          });
        } else {
          batchReport += `- None detected\n`;
        }
        
        batchReport += `\n✅ Low Risk Tools:\n`;
        const lowRiskTools = results.filter(r => r.riskLevel === 'LOW');
        if (lowRiskTools.length > 0) {
          lowRiskTools.forEach(tool => {
            batchReport += `- ${tool.name} (Score: ${tool.riskScore}/100)\n`;
          });
        } else {
          batchReport += `- None detected\n`;
        }
        
        batchReport += `\n💡 Recommendations:\n`;
        if (highRiskTools.length > 0) {
          batchReport += `- ⚠️ Review and potentially remove high-risk tools\n`;
          batchReport += `- 🔒 Implement additional security controls\n`;
        }
        if (mediumRiskTools.length > 0) {
          batchReport += `- 🔍 Monitor medium-risk tools closely\n`;
          batchReport += `- 🧪 Test in isolated environments\n`;
        }
        batchReport += `- 📝 Implement comprehensive audit logging\n`;
        batchReport += `- 🔄 Regular security reviews recommended\n`;
        
        return {
          content: [{
            type: 'text',
            text: batchReport
          }]
        };
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : 'Unknown error occurred';
        return {
          content: [{
            type: 'text',
            text: `Error in batch analysis: ${errorMessage}`
          }]
        };
      }
    }

    throw new Error(`Unknown tool: ${name}`);
  });

  // Handle resources/list method
  server.setRequestHandler(ListResourcesRequestSchema, async () => {
    return {
      resources: []
    };
  });

  // Handle prompts/list method
  server.setRequestHandler(ListPromptsRequestSchema, async () => {
    return {
      prompts: []
    };
  });

  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error('MCP Analyzer Server started - Security Analysis Ready!');
}

main().catch(console.error); 