import React, { useState, useEffect } from 'react';
import { Clock, Trash2, Plus, Calendar } from 'lucide-react';
import axios from 'axios';

interface Schedule {
    id: string;
    target: string;
    profile: string;
    cron_expression: string;
    next_run: number;
    active: boolean;
    webhook_url?: string;
}

export const ScheduleManager: React.FC = () => {
    const [schedules, setSchedules] = useState<Schedule[]>([]);
    const [showForm, setShowForm] = useState(false);

    // Form state
    const [target, setTarget] = useState('');
    const [profile, setProfile] = useState('normal');
    const [frequency, setFrequency] = useState('daily');
    const [customCron, setCustomCron] = useState('');
    const [webhookUrl, setWebhookUrl] = useState('');

    const fetchSchedules = async () => {
        try {
            const res = await axios.get('/api/schedules');
            setSchedules(res.data);
        } catch (e) {
            console.error("Failed to fetch schedules", e);
        }
    };

    useEffect(() => {
        fetchSchedules();
        const interval = setInterval(fetchSchedules, 30000); // Poll updates
        return () => clearInterval(interval);
    }, []);

    const handleDelete = async (id: string) => {
        if (!confirm('Delete this schedule?')) return;
        await axios.delete(`/api/schedules/${id}`);
        fetchSchedules();
    };

    const handleCreate = async (e: React.FormEvent) => {
        e.preventDefault();
        let cron = customCron;
        if (frequency === 'daily') cron = '0 0 2 * * *'; // 2 AM Daily
        if (frequency === 'weekly') cron = '0 0 2 * * 0'; // 2 AM Sunday
        if (frequency === 'hourly') cron = '0 0 * * * *'; // Every hour

        await axios.post('/api/schedules', {
            target,
            profile,
            cron_expression: cron,
            webhook_url: webhookUrl || null
        });

        setShowForm(false);
        setTarget('');
        fetchSchedules();
    };

    return (
        <div className="bg-gray-800 p-6 rounded-xl border border-gray-700 shadow-xl">
            <div className="flex justify-between items-center mb-6">
                <h2 className="text-xl font-bold flex items-center text-teal-400">
                    <Calendar className="mr-2" /> Scheduled Scans
                </h2>
                <button
                    onClick={() => setShowForm(!showForm)}
                    className="bg-teal-600 hover:bg-teal-700 text-white px-3 py-2 rounded flex items-center"
                >
                    <Plus size={16} className="mr-1" /> New Schedule
                </button>
            </div>

            {showForm && (
                <form onSubmit={handleCreate} className="mb-6 p-4 bg-gray-700 rounded-lg animate-fade-in">
                    <div className="grid grid-cols-2 gap-4 mb-4">
                        <div>
                            <label className="block text-sm text-gray-400 mb-1">Target</label>
                            <input
                                className="w-full bg-gray-800 border border-gray-600 rounded p-2 text-white"
                                value={target}
                                onChange={e => setTarget(e.target.value)}
                                placeholder="scanme.nmap.org"
                                required
                            />
                        </div>
                        <div>
                            <label className="block text-sm text-gray-400 mb-1">Profile</label>
                            <select
                                className="w-full bg-gray-800 border border-gray-600 rounded p-2 text-white"
                                value={profile}
                                onChange={e => setProfile(e.target.value)}
                            >
                                <option value="quick">Quick</option>
                                <option value="normal">Normal</option>
                                <option value="full">Full</option>
                                <option value="deep">Deep (Nuclei)</option>
                            </select>
                        </div>
                    </div>

                    <div className="mb-4">
                        <label className="block text-sm text-gray-400 mb-1">Frequency</label>
                        <select
                            className="w-full bg-gray-800 border border-gray-600 rounded p-2 text-white mb-2"
                            value={frequency}
                            onChange={e => setFrequency(e.target.value)}
                        >
                            <option value="daily">Daily (2 AM)</option>
                            <option value="weekly">Weekly (Sunday 2 AM)</option>
                            <option value="hourly">Hourly</option>
                            <option value="custom">Custom Cron</option>
                        </select>

                        {frequency === 'custom' && (
                            <input
                                className="w-full bg-gray-800 border border-gray-600 rounded p-2 text-white font-mono mt-2"
                                value={customCron}
                                onChange={e => setCustomCron(e.target.value)}
                                placeholder="0 0 * * * *"
                                required
                            />
                        )}
                    </div>

                    <div className="mb-4">
                        <label className="block text-sm text-gray-400 mb-1">Webhook URL (Discord/Slack - Optional)</label>
                        <input
                            className="w-full bg-gray-800 border border-gray-600 rounded p-2 text-white text-xs"
                            value={webhookUrl}
                            onChange={e => setWebhookUrl(e.target.value)}
                            placeholder="https://discord.com/api/webhooks/..."
                        />
                    </div>

                    <div className="flex justify-end gap-2">
                        <button type="button" onClick={() => setShowForm(false)} className="px-4 py-2 text-gray-400 hover:text-white">Cancel</button>
                        <button type="submit" className="px-4 py-2 bg-teal-500 hover:bg-teal-600 text-white rounded">Save Schedule</button>
                    </div>
                </form>
            )}

            {schedules.length === 0 ? (
                <div className="text-gray-500 text-center py-8">No active schedules</div>
            ) : (
                <div className="space-y-4">
                    {schedules.map(s => (
                        <div key={s.id} className="flex justify-between items-center bg-gray-900 p-4 rounded-lg border border-gray-700">
                            <div>
                                <div className="font-bold text-white flex items-center">
                                    {s.target}
                                    <span className="ml-2 text-xs bg-gray-700 px-2 py-0.5 rounded text-gray-300">{s.profile}</span>
                                </div>
                                <div className="text-sm text-gray-400 flex items-center mt-1">
                                    <Clock size={14} className="mr-1" /> {s.cron_expression}
                                    <span className="mx-2">•</span>
                                    Next: {new Date(s.next_run * 1000).toLocaleString()}
                                </div>
                            </div>
                            <div className="flex gap-2">
                                <button onClick={() => handleDelete(s.id)} className="text-red-400 hover:text-red-300 p-2 hover:bg-gray-800 rounded">
                                    <Trash2 size={18} />
                                </button>
                            </div>
                        </div>
                    ))}
                </div>
            )}
        </div>
    );
};
