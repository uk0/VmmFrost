namespace VmmFrost.ScatterAPI
{
    public interface IScatterEntry
    {
        /// <summary>
        /// Entry Index
        /// </summary>
        public int Index { get; init; }
        /// <summary>
        /// Entry ID
        /// </summary>
        public int Id { get; init; }
        /// <summary>
        /// Can be an ulong or another ScatterReadEntry
        /// </summary>
        public object Addr { get; set; }
        /// <summary>
        /// Offset amount to be added to Address.
        /// </summary>
        public uint Offset { get; init; }
        /// <summary>
        /// Defines the type.
        /// </summary>
        public Type Type { get; }
        /// <summary>
        /// Can be an int32 or another ScatterReadEntry
        /// </summary>
        public object Size { get; set; }
        /// <summary>
        /// True if the scatter read has failed. Result will also be null.
        /// </summary>
        public bool IsFailed { get; set; }

        /// <summary>
        /// Sets the Result for this Scatter Read.
        /// </summary>
        /// <param name="buffer">Raw memory buffer for this read.</param>
        void SetResult(byte[] buffer);

        /// <summary>
        /// Parses the address to read for this Scatter Read.
        /// Sets the Addr property for the object.
        /// </summary>
        /// <returns>Virtual address to read.</returns>
        ulong ParseAddr();

        /// <summary>
        /// Parses the number of bytes to read for this Scatter Read.
        /// Sets the Size property for the object.
        /// </summary>
        /// <returns>Size of read.</returns>
        int ParseSize();

        /// <summary>
        /// Tries to return the Scatter Read Result.
        /// </summary>
        /// <typeparam name="TOut">Type to return.</typeparam>
        /// <param name="result">Result to populate.</param>
        /// <returns>True if successful, otherwise False.</returns>
        bool TryGetResult<TOut>(out TOut result);
    }
}
