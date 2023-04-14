﻿namespace VmmFrost.ScatterAPI
{
    /// <summary>
    /// Top level object defining a scatter read operation. Create one of these in a local context.
    /// </summary>
    public class ScatterReadMap
    {
        protected List<ScatterReadRound> Rounds { get; } = new();
        protected Dictionary<int, Dictionary<int, IScatterEntry>> _results { get; } = new();
        /// <summary>
        /// Contains results from Scatter Read after Execute() is performed. First key is Index, Second Key ID.
        /// </summary>
        public IReadOnlyDictionary<int, Dictionary<int, IScatterEntry>> Results => _results;

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="indexCount">Number of indexes in the scatter read loop.</param>
        public ScatterReadMap(int indexCount)
        {
            for (int i = 0; i < indexCount; i++)
            {
                _results.Add(i, new());
            }
        }

        /// <summary>
        /// Executes Scatter Read operation as defined per the map.
        /// </summary>
        public void Execute(MemDMA mem)
        {
            foreach (var round in Rounds)
            {
                round.Run(mem);
            }
        }
        /// <summary>
        /// (Base)
        /// Add scatter read rounds to the operation. Each round is a successive scatter read, you may need multiple
        /// rounds if you have reads dependent on earlier scatter reads result(s).
        /// </summary>
        /// <returns>ScatterReadRound object.</returns>
        public virtual ScatterReadRound AddRound(bool useCache = true)
        {
            var round = new ScatterReadRound(_results, useCache);
            Rounds.Add(round);
            return round;
        }
    }
}