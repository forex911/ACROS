import React, { useRef, useEffect, useCallback } from 'react';

interface SeriesConfig {
  key: string;
  label: string;
  color: string;
  glowColor: string;
}

interface LiveChartProps {
  data: Record<string, number>[];
  series: SeriesConfig[];
  height?: number;
  dangerThreshold?: number;
}

export const LiveChart: React.FC<LiveChartProps> = ({
  data,
  series,
  height = 420,
  dangerThreshold = 80,
}) => {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const animRef = useRef<number>(0);
  const offsetRef = useRef<number>(0);
  const prevDataLenRef = useRef<number>(0);

  const draw = useCallback(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const dpr = window.devicePixelRatio || 1;
    const rect = canvas.getBoundingClientRect();
    canvas.width = rect.width * dpr;
    canvas.height = rect.height * dpr;
    ctx.scale(dpr, dpr);

    const W = rect.width;
    const H = rect.height;
    const padTop = 30;
    const padBot = 40;
    const padLeft = 50;
    const padRight = 20;
    const chartW = W - padLeft - padRight;
    const chartH = H - padTop - padBot;

    // Clear
    ctx.clearRect(0, 0, W, H);

    // If new data arrived, animate the offset
    if (data.length > prevDataLenRef.current && prevDataLenRef.current > 0) {
      offsetRef.current = chartW / Math.max(data.length - 1, 1);
    }
    prevDataLenRef.current = data.length;

    // Ease the offset toward 0
    if (offsetRef.current > 0.5) {
      offsetRef.current *= 0.88; // smooth decay
    } else {
      offsetRef.current = 0;
    }

    const xShift = -offsetRef.current;

    // Y-axis scale: 0–100
    const yMin = 0;
    const yMax = 100;
    const toX = (i: number) => padLeft + (i / Math.max(data.length - 1, 1)) * chartW + xShift;
    const toY = (v: number) => padTop + chartH - ((v - yMin) / (yMax - yMin)) * chartH;

    // ── Grid lines ──────────────────────────────────────
    ctx.strokeStyle = '#1a1a1a';
    ctx.lineWidth = 1;
    const gridSteps = [0, 20, 40, 60, 80, 100];
    for (const step of gridSteps) {
      const y = toY(step);
      ctx.beginPath();
      ctx.setLineDash([3, 3]);
      ctx.moveTo(padLeft, y);
      ctx.lineTo(W - padRight, y);
      ctx.stroke();
      ctx.setLineDash([]);

      // Y labels
      ctx.fillStyle = '#666666';
      ctx.font = '10px "Space Mono", monospace';
      ctx.textAlign = 'right';
      ctx.fillText(`${step}%`, padLeft - 8, y + 3);
    }

    // ── Danger zone ─────────────────────────────────────
    const dangerY = toY(dangerThreshold);
    ctx.strokeStyle = 'rgba(239, 68, 68, 0.4)';
    ctx.lineWidth = 1;
    ctx.setLineDash([6, 4]);
    ctx.beginPath();
    ctx.moveTo(padLeft, dangerY);
    ctx.lineTo(W - padRight, dangerY);
    ctx.stroke();
    ctx.setLineDash([]);

    ctx.fillStyle = 'rgba(239, 68, 68, 0.5)';
    ctx.font = 'bold 9px "Space Mono", monospace';
    ctx.textAlign = 'right';
    ctx.fillText('DANGER', W - padRight, dangerY - 6);

    // ── X-axis time labels ──────────────────────────────
    if (data.length > 0) {
      ctx.fillStyle = '#666666';
      ctx.font = '9px "Space Mono", monospace';
      ctx.textAlign = 'center';
      const labelInterval = Math.max(1, Math.floor(data.length / 6));
      for (let i = 0; i < data.length; i += labelInterval) {
        const x = toX(i);
        if (x >= padLeft && x <= W - padRight) {
          const label = (data[i] as any).time || '';
          ctx.fillText(label, x, H - padBot + 20);
        }
      }
      // Always draw last label
      const lastX = toX(data.length - 1);
      if (lastX >= padLeft && lastX <= W - padRight) {
        const lastLabel = (data[data.length - 1] as any).time || '';
        ctx.fillText(lastLabel, lastX, H - padBot + 20);
      }
    }

    if (data.length < 2) {
      ctx.fillStyle = '#666666';
      ctx.font = '12px "Space Mono", monospace';
      ctx.textAlign = 'center';
      ctx.fillText('Collecting data...', W / 2, H / 2);
      animRef.current = requestAnimationFrame(draw);
      return;
    }

    // ── Draw each series ────────────────────────────────
    // Helper: smooth bezier through points
    const drawSmoothLine = (points: { x: number; y: number }[]) => {
      if (points.length < 2) return;
      ctx.moveTo(points[0].x, points[0].y);
      for (let i = 1; i < points.length; i++) {
        const prev = points[i - 1];
        const curr = points[i];
        const cpx = (prev.x + curr.x) / 2;
        ctx.bezierCurveTo(cpx, prev.y, cpx, curr.y, curr.x, curr.y);
      }
    };

    for (const s of series) {
      const points = data.map((d, i) => ({
        x: toX(i),
        y: toY(d[s.key] ?? 0),
      }));

      // ── Gradient fill ───────────────────────────────
      const grad = ctx.createLinearGradient(0, padTop, 0, padTop + chartH);
      const rgb = hexToRgb(s.color);
      grad.addColorStop(0, `rgba(${rgb}, 0.3)`);
      grad.addColorStop(0.5, `rgba(${rgb}, 0.06)`);
      grad.addColorStop(1, `rgba(${rgb}, 0)`);

      ctx.save();
      ctx.beginPath();
      ctx.rect(padLeft, padTop, chartW, chartH);
      ctx.clip();

      ctx.beginPath();
      drawSmoothLine(points);
      // Close the area
      ctx.lineTo(points[points.length - 1].x, padTop + chartH);
      ctx.lineTo(points[0].x, padTop + chartH);
      ctx.closePath();
      ctx.fillStyle = grad;
      ctx.fill();

      // ── Glow line ───────────────────────────────────
      ctx.beginPath();
      drawSmoothLine(points);
      ctx.strokeStyle = s.glowColor;
      ctx.lineWidth = 6;
      ctx.globalAlpha = 0.15;
      ctx.stroke();
      ctx.globalAlpha = 1;

      // ── Main line ───────────────────────────────────
      ctx.beginPath();
      drawSmoothLine(points);
      ctx.strokeStyle = s.color;
      ctx.lineWidth = 2;
      ctx.stroke();

      ctx.restore();

      // ── Pulsing dot on last point ───────────────────
      const lastPt = points[points.length - 1];
      if (lastPt.x >= padLeft && lastPt.x <= W - padRight) {
        const pulseRadius = 4 + Math.sin(Date.now() / 300) * 2;

        // Outer pulse ring
        ctx.beginPath();
        ctx.arc(lastPt.x, lastPt.y, pulseRadius + 4, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(${rgb}, ${0.15 + Math.sin(Date.now() / 300) * 0.1})`;
        ctx.fill();

        // Solid dot
        ctx.beginPath();
        ctx.arc(lastPt.x, lastPt.y, 4, 0, Math.PI * 2);
        ctx.fillStyle = s.color;
        ctx.fill();

        // Inner highlight
        ctx.beginPath();
        ctx.arc(lastPt.x, lastPt.y, 1.5, 0, Math.PI * 2);
        ctx.fillStyle = '#000000';
        ctx.fill();
      }
    }

    animRef.current = requestAnimationFrame(draw);
  }, [data, series, dangerThreshold]);

  useEffect(() => {
    animRef.current = requestAnimationFrame(draw);
    return () => cancelAnimationFrame(animRef.current);
  }, [draw]);

  // Resize observer
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const observer = new ResizeObserver(() => {
      // re-render on size change
    });
    observer.observe(canvas);
    return () => observer.disconnect();
  }, []);

  return (
    <canvas
      ref={canvasRef}
      className="w-full block"
      style={{ height: `${height}px` }}
    />
  );
};

function hexToRgb(hex: string): string {
  const r = parseInt(hex.slice(1, 3), 16);
  const g = parseInt(hex.slice(3, 5), 16);
  const b = parseInt(hex.slice(5, 7), 16);
  return `${r},${g},${b}`;
}
