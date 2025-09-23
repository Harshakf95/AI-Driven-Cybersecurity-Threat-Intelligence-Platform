import React, { useEffect, useRef } from 'react';
import { useThreatData } from '../../context/ThreatContext';
import { Shield, AlertCircle } from 'lucide-react';

const ThreatScoreGauge: React.FC = () => {
  const { systemMetrics } = useThreatData();
  const { threatScore } = systemMetrics;
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    if (!canvasRef.current) return;
    
    const canvas = canvasRef.current;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    // Clear canvas
    ctx.clearRect(0, 0, canvas.width, canvas.height);

    // Set up gauge
    const centerX = canvas.width / 2;
    const centerY = canvas.height - 30;
    const radius = Math.min(centerX, centerY) - 10;
    
    // Draw gauge background
    ctx.beginPath();
    ctx.arc(centerX, centerY, radius, Math.PI, 2 * Math.PI, false);
    ctx.lineWidth = 20;
    ctx.strokeStyle = '#1f2937'; // Gray background
    ctx.stroke();

    // Calculate score color
    let scoreColor = '#10b981'; // Green for low threat
    if (threatScore > 30 && threatScore <= 60) {
      scoreColor = '#f59e0b'; // Amber for medium threat
    } else if (threatScore > 60) {
      scoreColor = '#ef4444'; // Red for high threat
    }

    // Draw score value
    const scoreRatio = threatScore / 100;
    const startAngle = Math.PI;
    const endAngle = startAngle + scoreRatio * Math.PI;
    
    ctx.beginPath();
    ctx.arc(centerX, centerY, radius, startAngle, endAngle, false);
    ctx.lineWidth = 20;
    ctx.strokeStyle = scoreColor;
    ctx.stroke();

    // Add needle
    ctx.save();
    ctx.translate(centerX, centerY);
    ctx.rotate(startAngle + scoreRatio * Math.PI);
    
    ctx.beginPath();
    ctx.moveTo(-5, 0);
    ctx.lineTo(0, -radius - 10);
    ctx.lineTo(5, 0);
    ctx.fillStyle = scoreColor;
    ctx.fill();
    
    // Add circle at base of needle
    ctx.beginPath();
    ctx.arc(0, 0, 7, 0, 2 * Math.PI);
    ctx.fillStyle = scoreColor;
    ctx.fill();
    
    ctx.restore();
  }, [threatScore]);

  // Determine threat level text
  const getThreatLevelText = () => {
    if (threatScore <= 30) return 'Low';
    if (threatScore <= 60) return 'Medium';
    return 'High';
  };

  // Determine threat level icon
  const getThreatLevelIcon = () => {
    if (threatScore <= 30) {
      return <Shield className="h-5 w-5 text-green-500" />;
    }
    if (threatScore <= 60) {
      return <AlertCircle className="h-5 w-5 text-amber-500" />;
    }
    return <AlertCircle className="h-5 w-5 text-red-500" />;
  };

  return (
    <div className="flex flex-col items-center p-4 h-full">
      <div className="flex items-center mb-2">
        {getThreatLevelIcon()}
        <h3 className="text-lg font-bold ml-2">
          {getThreatLevelText()} Threat Level
        </h3>
      </div>
      
      <div className="text-4xl font-bold mb-2" style={{ color: threatScore <= 30 ? '#10b981' : threatScore <= 60 ? '#f59e0b' : '#ef4444' }}>
        {threatScore}
      </div>
      
      <canvas
        ref={canvasRef}
        width={200}
        height={120}
        className="w-full h-auto"
      />
      
      <div className="w-full flex justify-between px-4 mt-2 text-xs text-gray-400">
        <span>0</span>
        <span>50</span>
        <span>100</span>
      </div>
    </div>
  );
};

export default ThreatScoreGauge;