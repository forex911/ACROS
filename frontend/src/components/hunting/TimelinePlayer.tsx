import React, { useState, useEffect } from 'react';
import { Play, Pause, FastForward, Rewind, Activity, Network, FileTerminal } from 'lucide-react';
import api from '../../api/client';

interface TimelineEvent {
  type: 'process' | 'network';
  data: any;
}

interface TimelinePlayerProps {
  jobId: string;
}

export const TimelinePlayer: React.FC<TimelinePlayerProps> = ({ jobId }) => {
  const [events, setEvents] = useState<TimelineEvent[]>([]);
  const [currentIndex, setCurrentIndex] = useState(0);
  const [isPlaying, setIsPlaying] = useState(false);
  const [speed, setSpeed] = useState(1000);

  useEffect(() => {
    const fetchTimeline = async () => {
      try {
        const response = await api.get(`/jobs/${jobId}/timeline`);
        setEvents(response.data.events);
      } catch (error) {
        console.error("Failed to fetch timeline", error);
      }
    };
    fetchTimeline();
  }, [jobId]);

  useEffect(() => {
    let interval: number;
    if (isPlaying && currentIndex < events.length - 1) {
      interval = window.setInterval(() => {
        setCurrentIndex(prev => prev + 1);
      }, speed);
    } else if (currentIndex >= events.length - 1) {
      setIsPlaying(false);
    }
    return () => clearInterval(interval);
  }, [isPlaying, currentIndex, events.length, speed]);

  const togglePlay = () => setIsPlaying(!isPlaying);
  const reset = () => setCurrentIndex(0);
  const changeSpeed = () => setSpeed(s => s === 1000 ? 500 : s === 500 ? 250 : 1000);

  if (events.length === 0) {
    return <div className="text-gray-500 font-mono text-sm p-4">Loading timeline or no events available...</div>;
  }

  const currentEvent = events[currentIndex];

  return (
    <div className="flex flex-col bg-cyber-panel border border-cyber-border rounded-lg p-4 font-mono w-full max-w-4xl mx-auto">
      <div className="flex items-center justify-between mb-4 border-b border-cyber-border pb-2">
        <h3 className="text-cyber-accent font-bold tracking-wider">EXECUTION_TIMELINE_REPLAY</h3>
        <div className="flex items-center gap-4">
          <span className="text-xs text-gray-400">SPEED: {1000 / speed}x</span>
          <span className="text-xs text-cyber-green bg-cyber-green/10 px-2 py-1 rounded">
            EVENT {currentIndex + 1} / {events.length}
          </span>
        </div>
      </div>

      {/* Scrubber / Visual Timeline */}
      <div className="relative w-full h-2 bg-gray-800 rounded mb-6">
        <div 
          className="absolute top-0 left-0 h-full bg-cyber-accent rounded transition-all duration-300"
          style={{ width: `${((currentIndex + 1) / events.length) * 100}%` }}
        />
      </div>

      {/* Controls */}
      <div className="flex items-center justify-center gap-4 mb-6">
        <button onClick={reset} className="p-2 text-gray-400 hover:text-white hover:bg-gray-700 rounded transition-colors">
          <Rewind size={20} />
        </button>
        <button onClick={togglePlay} className="p-3 bg-cyber-accent/20 text-cyber-accent hover:bg-cyber-accent/40 rounded-full transition-colors">
          {isPlaying ? <Pause size={24} /> : <Play size={24} className="ml-1" />}
        </button>
        <button onClick={changeSpeed} className="p-2 text-gray-400 hover:text-white hover:bg-gray-700 rounded transition-colors">
          <FastForward size={20} />
        </button>
      </div>

      {/* Event Display */}
      <div className="flex-1 bg-cyber-dark p-4 rounded border border-gray-800 min-h-[150px] shadow-inner">
        {currentEvent.type === 'process' ? (
           <div className="flex items-start gap-4 animate-in fade-in slide-in-from-bottom-2 duration-300">
             <div className="p-2 bg-blue-500/10 text-blue-400 rounded">
                <FileTerminal size={24} />
             </div>
             <div>
                <h4 className="text-blue-400 font-bold mb-1">Process Execution</h4>
                <p className="text-sm text-gray-300">PID: <span className="text-gray-100">{currentEvent.data.pid}</span></p>
                <p className="text-sm text-gray-300">Executable: <span className="text-gray-100">{currentEvent.data.executable}</span></p>
                <p className="text-sm text-gray-300">Command: <span className="text-gray-100 break-all">{currentEvent.data.command}</span></p>
             </div>
           </div>
        ) : (
           <div className="flex items-start gap-4 animate-in fade-in slide-in-from-bottom-2 duration-300">
             <div className="p-2 bg-cyber-alert/10 text-cyber-alert rounded">
                <Network size={24} />
             </div>
             <div>
                <h4 className="text-cyber-alert font-bold mb-1">Network Connection</h4>
                <p className="text-sm text-gray-300">Source PID: <span className="text-gray-100">{currentEvent.data.pid}</span></p>
                <p className="text-sm text-gray-300">Destination IP: <span className="text-gray-100">{currentEvent.data.ip}</span></p>
                <p className="text-sm text-gray-300">Port: <span className="text-gray-100">{currentEvent.data.port}</span></p>
             </div>
           </div>
        )}
      </div>
    </div>
  );
};
