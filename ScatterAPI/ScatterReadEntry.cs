﻿using System.Runtime.InteropServices;
using System.Text;

namespace VmmFrost.ScatterAPI
{
    /// <summary>
    /// Single scatter read  Use ScatterReadRound.AddEntry() to construct this class.
    /// </summary>
    public class ScatterReadEntry<T> : IScatterEntry
    {
        #region Properties

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
        public object Addr { get; set; } = (ulong)0x0;
        /// <summary>
        /// Offset amount to be added to Address.
        /// </summary>
        public uint Offset { get; init; } = 0x0;
        /// <summary>
        /// Defines the type.
        /// </summary>
        public Type Type { get; } = typeof(T);
        /// <summary>
        /// Can be an int32 or another ScatterReadEntry
        /// </summary>
        public object Size { get; set; }
        /// <summary>
        /// True if the scatter read has failed. Result will also be null.
        /// </summary>
        public bool IsFailed { get; set; } = false;
        /// <summary>
        /// Scatter Read Result.
        /// </summary>
        protected T Result { get; set; }
        #endregion

        #region Read Prep
        /// <summary>
        /// Parses the address to read for this Scatter Read.
        /// Sets the Addr property for the object.
        /// </summary>
        /// <returns>Virtual address to read.</returns>
        public ulong ParseAddr()
        {
            ulong addr = 0x0;
            if (this.Addr is ulong p1)
                addr = p1;
            else if (this.Addr is MemPointer p2)
                addr = p2;
            else if (this.Addr is IScatterEntry ptrObj) // Check if the addr references another ScatterRead Result
            {
                if (ptrObj.TryGetResult<MemPointer>(out var p3))
                    addr = p3;
                else
                    ptrObj.TryGetResult(out addr);
            }
            this.Addr = addr;
            return addr;
        }

        /// <summary>
        /// (Base)
        /// Parses the number of bytes to read for this Scatter Read.
        /// Sets the Size property for the object.
        /// Derived classes should call upon this Base.
        /// </summary>
        /// <returns>Size of read.</returns>
        public virtual int ParseSize()
        {
            int size = 0;
            if (this.Type.IsValueType)
                size = Marshal.SizeOf<T>();
            else if (this.Size is int sizeInt)
                size = sizeInt;
            else if (this.Size is IScatterEntry sizeObj) // Check if the size references another ScatterRead Result
                sizeObj.TryGetResult(out size);
            this.Size = size;
            return size;
        }
        #endregion

        #region Set Result
        /// <summary>
        /// Sets the Result for this Scatter Read.
        /// </summary>
        /// <param name="buffer">Raw memory buffer for this read.</param>
        public void SetResult(byte[] buffer)
        {
            try
            {
                if (IsFailed)
                    return;
                if (Type.IsValueType) /// Value Type
                    SetValueResult(buffer);
                else /// Ref Type
                    SetClassResult(buffer);
            }
            catch
            {
                IsFailed = true;
            }
        }

        /// <summary>
        /// Set the Result from a Value Type.
        /// </summary>
        /// <param name="buffer">Raw memory buffer for this read.</param>
#pragma warning disable CS8500
        private unsafe void SetValueResult(byte[] buffer)
        {
            if (buffer.Length != sizeof(T)) // Safety Check
                throw new ArgumentOutOfRangeException(nameof(buffer));
            fixed (void* pb = buffer)
            {
                Result = *(T*)pb;
            }
            if (Result is MemPointer ptr)
                ptr.Validate();
        }
#pragma warning restore CS8500

        /// <summary>
        /// (Base)
        /// Set the Result from a Class Type.
        /// Derived classes should call upon this Base.
        /// </summary>
        /// <param name="buffer">Raw memory buffer for this read.</param>
        protected virtual void SetClassResult(byte[] buffer)
        {
            if (Type == typeof(string))
            {
                var value = Encoding.Default.GetString(buffer).Split('\0')[0];
                if (value is T result) // We already know the Types match, this is to satisfy the compiler
                    Result = result;
            }
            else
                throw new NotImplementedException(nameof(Type));
        }
        #endregion

        #region Get Result
        /// <summary>
        /// Tries to return the Scatter Read Result.
        /// </summary>
        /// <typeparam name="TOut">Type to return.</typeparam>
        /// <param name="result">Result to populate.</param>
        /// <returns>True if successful, otherwise False.</returns>
        public bool TryGetResult<TOut>(out TOut result)
        {
            try
            {
                if (!IsFailed && Result is TOut tResult)
                {
                    result = tResult;
                    return true;
                }
                result = default;
                return false;
            }
            catch
            {
                result = default;
                return false;
            }
        }
        #endregion
    }
}
