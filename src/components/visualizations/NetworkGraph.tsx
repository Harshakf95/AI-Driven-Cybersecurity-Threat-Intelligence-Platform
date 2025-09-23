import React, { useEffect, useRef } from 'react';
import * as d3 from 'd3';
import { NetworkGraph as NetworkGraphType, GraphNode, GraphLink } from '../../types';
import { generateNetworkGraph } from '../../utils/threatGenerator';

const NetworkGraph: React.FC = () => {
  const svgRef = useRef<SVGSVGElement>(null);
  const tooltipRef = useRef<HTMLDivElement>(null);
  
  useEffect(() => {
    if (!svgRef.current || !tooltipRef.current) return;
    
    // Generate sample network data
    const graphData: NetworkGraphType = generateNetworkGraph();
    
    // Clear any existing visualization
    d3.select(svgRef.current).selectAll('*').remove();
    
    // Set up the SVG
    const svg = d3.select(svgRef.current);
    const width = svgRef.current.clientWidth;
    const height = svgRef.current.clientHeight || 400;
    
    // Create tooltip
    const tooltip = d3.select(tooltipRef.current)
      .style('position', 'absolute')
      .style('visibility', 'hidden')
      .style('padding', '10px')
      .style('background', 'rgba(22, 27, 34, 0.9)')
      .style('border-radius', '6px')
      .style('color', '#fff')
      .style('border', '1px solid #30363d')
      .style('font-size', '12px')
      .style('pointer-events', 'none')
      .style('z-index', '10');
    
    // Create the force simulation
    const simulation = d3.forceSimulation<GraphNode, GraphLink>(graphData.nodes)
      .force('link', d3.forceLink<GraphNode, GraphLink>(graphData.links).id((d: any) => d.id).distance(70))
      .force('charge', d3.forceManyBody().strength(-150))
      .force('center', d3.forceCenter(width / 2, height / 2))
      .force('collide', d3.forceCollide().radius(d => (d.value as number) * 2 + 10));
    
    // Create a group for links
    const link = svg.append('g')
      .attr('class', 'links')
      .selectAll('line')
      .data(graphData.links)
      .enter().append('line')
      .attr('stroke-width', d => Math.sqrt(d.value))
      .attr('stroke', d => {
        switch (d.status) {
          case 'malicious': return '#ef4444'; // Red
          case 'suspicious': return '#f59e0b'; // Amber
          default: return '#4f46e5'; // Indigo
        }
      })
      .attr('stroke-opacity', 0.6)
      .attr('class', d => d.status || 'normal');
    
    // Create a group for nodes
    const node = svg.append('g')
      .attr('class', 'nodes')
      .selectAll('circle')
      .data(graphData.nodes)
      .enter().append('circle')
      .attr('r', d => d.value)
      .attr('fill', d => {
        if (d.type === 'target') return '#3b82f6'; // Blue for target/server
        if (d.type === 'router') return '#8b5cf6'; // Purple for routers
        if (d.threat) return '#ef4444'; // Red for threats
        return '#10b981'; // Green for normal sources
      })
      .attr('stroke', d => d.anomaly ? '#f59e0b' : 'none') // Amber stroke for anomalies
      .attr('stroke-width', 2)
      .call(d3.drag<SVGCircleElement, GraphNode>()
        .on('start', dragstarted)
        .on('drag', dragged)
        .on('end', dragended));
    
    // Add pulsating animation for threat nodes
    node.filter(d => d.threat)
      .append('animate')
      .attr('attributeName', 'r')
      .attr('values', d => `${d.value};${d.value * 1.3};${d.value}`)
      .attr('dur', '2s')
      .attr('repeatCount', 'indefinite');
    
    // Add hover effects
    node.on('mouseover', function(event, d) {
      d3.select(this).attr('stroke', '#fff').attr('stroke-width', 2);
      
      const tooltipContent = `
        <div>
          <div style="font-weight: bold; margin-bottom: 4px;">${d.name}</div>
          <div>Type: ${d.type.charAt(0).toUpperCase() + d.type.slice(1)}</div>
          ${d.threat ? '<div style="color: #ef4444;">Threat Detected</div>' : ''}
          ${d.anomaly ? '<div style="color: #f59e0b;">Anomalous Behavior</div>' : ''}
        </div>
      `;
      
      tooltip
        .html(tooltipContent)
        .style('visibility', 'visible')
        .style('left', `${event.pageX + 15}px`)
        .style('top', `${event.pageY - 20}px`);
    })
    .on('mousemove', function(event) {
      tooltip
        .style('left', `${event.pageX + 15}px`)
        .style('top', `${event.pageY - 20}px`);
    })
    .on('mouseout', function() {
      d3.select(this)
        .attr('stroke', d => d.anomaly ? '#f59e0b' : 'none')
        .attr('stroke-width', d => d.anomaly ? 2 : 0);
      
      tooltip.style('visibility', 'hidden');
    });
    
    // Add title to nodes
    node.append('title')
      .text(d => d.name);
    
    // Update positions on each simulation tick
    simulation.on('tick', () => {
      link
        .attr('x1', d => (d.source as any).x)
        .attr('y1', d => (d.source as any).y)
        .attr('x2', d => (d.target as any).x)
        .attr('y2', d => (d.target as any).y);
      
      node
        .attr('cx', d => d.x = Math.max(d.value, Math.min(width - d.value, d.x)))
        .attr('cy', d => d.y = Math.max(d.value, Math.min(height - d.value, d.y)));
    });
    
    // Functions for drag behavior
    function dragstarted(event: any, d: any) {
      if (!event.active) simulation.alphaTarget(0.3).restart();
      d.fx = d.x;
      d.fy = d.y;
    }
    
    function dragged(event: any, d: any) {
      d.fx = event.x;
      d.fy = event.y;
    }
    
    function dragended(event: any, d: any) {
      if (!event.active) simulation.alphaTarget(0);
      d.fx = null;
      d.fy = null;
    }
    
    // Add legend
    const legend = svg.append('g')
      .attr('class', 'legend')
      .attr('transform', 'translate(20, 20)');
    
    const legendItems = [
      { label: 'Server', color: '#3b82f6', threat: false, anomaly: false },
      { label: 'Router', color: '#8b5cf6', threat: false, anomaly: false },
      { label: 'Client', color: '#10b981', threat: false, anomaly: false },
      { label: 'Threat', color: '#ef4444', threat: true, anomaly: false },
      { label: 'Anomaly', color: '#10b981', threat: false, anomaly: true },
    ];
    
    legendItems.forEach((item, i) => {
      const legendItem = legend.append('g')
        .attr('transform', `translate(0, ${i * 25})`);
      
      legendItem.append('circle')
        .attr('r', 6)
        .attr('fill', item.color)
        .attr('stroke', item.anomaly ? '#f59e0b' : 'none')
        .attr('stroke-width', item.anomaly ? 2 : 0);
      
      if (item.threat) {
        legendItem.append('circle')
          .attr('r', 6)
          .attr('fill', 'none')
          .attr('stroke', '#fff')
          .attr('stroke-width', 1)
          .attr('stroke-dasharray', '2,2')
          .attr('opacity', 0.7);
      }
      
      legendItem.append('text')
        .attr('x', 15)
        .attr('y', 5)
        .text(item.label)
        .attr('fill', '#d1d5db')
        .style('font-size', '12px');
    });
    
    // Cleanup
    return () => {
      simulation.stop();
    };
  }, []);

  return (
    <div className="relative h-full w-full">
      <svg ref={svgRef} className="w-full h-96 rounded-lg border border-gray-700" />
      <div ref={tooltipRef} className="absolute top-0 left-0 pointer-events-none" />
    </div>
  );
};

export default NetworkGraph;