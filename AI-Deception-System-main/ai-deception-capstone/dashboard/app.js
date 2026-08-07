const { useState, useEffect } = React;

const Dashboard = () => {
    return (
        <div className="bg-slate-900 text-slate-100 min-h-screen p-6 font-sans">
            <header className="flex justify-between items-center mb-8 border-b border-slate-800 pb-4">
                <h1 className="text-2xl font-bold text-emerald-400">DeceptionNet / SOC Console</h1>
                <span className="text-sm text-emerald-400 bg-emerald-950 px-3 py-1 rounded border border-emerald-800">Status: Monitoring Active</span>
            </header>
            
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
                <div className="bg-slate-800 p-5 rounded-lg border border-slate-700 shadow">
                    <h3 className="text-slate-400 text-sm uppercase">Total Logs Analyzed</h3>
                    <div className="text-4xl font-bold text-white mt-2">10,000</div>
                </div>
                <div className="bg-slate-800 p-5 rounded-lg border border-slate-700 shadow">
                    <h3 className="text-slate-400 text-sm uppercase">Canary Tokens Triggered</h3>
                    <div className="text-4xl font-bold text-red-400 mt-2">1</div>
                </div>
                <div className="bg-slate-800 p-5 rounded-lg border border-slate-700 shadow">
                    <h3 className="text-slate-400 text-sm uppercase">ML Anomalies Flagged</h3>
                    <div className="text-4xl font-bold text-amber-400 mt-2">800</div>
                </div>
            </div>
        </div>
    );
};