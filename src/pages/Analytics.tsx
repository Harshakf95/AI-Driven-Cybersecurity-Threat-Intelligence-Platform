import React from 'react';
import { useThreatData } from '../context/ThreatContext';
import { BarChart2, TrendingUp, TrendingDown, Activity, Shield, Clock } from 'lucide-react';
import { Line } from 'react-chartjs-2';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend
} from 'chart.js';

ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend
);

const Analytics: React.FC = () => {
  const { threatData } = useThreatData();

  // Sample data for the charts
  const threatTrendData = {
    labels: ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun'],
    datasets: [
      {
        label: 'Web Threats',
        data: [65, 59, 80, 81, 56, 55],
        borderColor: 'rgb(75, 192, 192)',
        tension: 0.1
      },
      {
        label: 'Network Threats',
        data: [28, 48, 40, 19, 86, 27],
        borderColor: 'rgb(255, 99, 132)',
        tension: 0.1
      }
    ]
  };

  const options = {
    responsive: true,
    plugins: {
      legend: {
        position: 'top' as const,
        labels: {
          color: '#fff'
        }
      }
    },
    scales: {
      y: {
        grid: {
          color: '#374151'
        },
        ticks: {
          color: '#9CA3AF'
        }
      },
      x: {
        grid: {
          color: '#374151'
        },
        ticks: {
          color: '#9CA3AF'
        }
      }
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h1 className="text-2xl font-bold flex items-center">
          <BarChart2 className="mr-2 h-6 w-6 text-blue-500" />
          Threat Analytics
        </h1>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="dashboard-card p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-sm">Total Threats</p>
              <h3 className="text-2xl font-bold mt-1">1,284</h3>
            </div>
            <Activity className="h-8 w-8 text-blue-500" />
          </div>
          <div className="mt-4">
            <div className="flex items-center">
              <TrendingUp className="h-4 w-4 text-green-500 mr-1" />
              <span className="text-green-500 text-sm">12% increase</span>
            </div>
            <p className="text-gray-400 text-sm mt-1">compared to last month</p>
          </div>
        </div>

        <div className="dashboard-card p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-sm">Blocked Attacks</p>
              <h3 className="text-2xl font-bold mt-1">956</h3>
            </div>
            <Shield className="h-8 w-8 text-green-500" />
          </div>
          <div className="mt-4">
            <div className="flex items-center">
              <TrendingUp className="h-4 w-4 text-green-500 mr-1" />
              <span className="text-green-500 text-sm">8% increase</span>
            </div>
            <p className="text-gray-400 text-sm mt-1">in prevention rate</p>
          </div>
        </div>

        <div className="dashboard-card p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-sm">Average Response Time</p>
              <h3 className="text-2xl font-bold mt-1">1.2s</h3>
            </div>
            <Clock className="h-8 w-8 text-amber-500" />
          </div>
          <div className="mt-4">
            <div className="flex items-center">
              <TrendingDown className="h-4 w-4 text-red-500 mr-1" />
              <span className="text-red-500 text-sm">3% slower</span>
            </div>
            <p className="text-gray-400 text-sm mt-1">than last week</p>
          </div>
        </div>
      </div>

      <div className="dashboard-card p-6">
        <h2 className="text-xl font-semibold mb-4">Threat Trend Analysis</h2>
        <div className="h-96">
          <Line data={threatTrendData} options={options} />
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="dashboard-card p-6">
          <h2 className="text-xl font-semibold mb-4">Top Attack Vectors</h2>
          <div className="space-y-4">
            {[
              { name: 'SQL Injection', percentage: 35 },
              { name: 'XSS Attacks', percentage: 28 },
              { name: 'DDoS Attempts', percentage: 20 },
              { name: 'Brute Force', percentage: 17 }
            ].map((vector) => (
              <div key={vector.name}>
                <div className="flex justify-between text-sm mb-1">
                  <span>{vector.name}</span>
                  <span>{vector.percentage}%</span>
                </div>
                <div className="w-full bg-gray-700 rounded-full h-2">
                  <div
                    className="bg-blue-500 h-2 rounded-full"
                    style={{ width: `${vector.percentage}%` }}
                  ></div>
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className="dashboard-card p-6">
          <h2 className="text-xl font-semibold mb-4">Geographic Distribution</h2>
          <div className="space-y-4">
            {[
              { country: 'United States', threats: 456 },
              { country: 'China', threats: 389 },
              { country: 'Russia', threats: 245 },
              { country: 'Brazil', threats: 198 }
            ].map((location) => (
              <div key={location.country} className="flex items-center justify-between">
                <span>{location.country}</span>
                <span className="text-blue-500 font-semibold">{location.threats}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};

export default Analytics;