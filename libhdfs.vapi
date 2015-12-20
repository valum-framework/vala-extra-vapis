/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

[CCode (cheader_include = "hdfs.h")]
namespace HDFS
{
	[Flags]
	public enum FileOpenFlags {
		[CCode (cname = "O_RDONLY")]
		READ_ONLY,
		[CCode (cname = "O_WRONLY")]
		WRITE_ONLY
	}

	[CCode (cname = "tObjectKind")]
	public enum FileType {
		[CCode (cname = "tObjectKindFile")]
		FILE,
		[CCode (cname = "tObjectKindDirectory")]
		DIRECTORY
	}

	[CCode (cname = "hdfsStreamType")]
	public enum StreamType {
		UNINITIALIZED,
		INPUT,
		OUTPUT
	}

	[CCode (cname = "hdfsFile")]
	public struct File
	{
		public StreamType type;
		public bool is_open_for_read ();
		public bool is_open_for_write ();
	}

	[Compact]
	[CCode (cname = "hdfsBuilder", free_function = "hdfsFreeBuilder", has_type_id = false)]
	public class Builder
	{
		public string? name_node {
			[CCode (cname = "hdfsBuilderSetNodeName")]
			set;
		}

		public uint16 name_node_port {
			[CCode (cname = "hdfsBuilderSetNodeNamePort")]
			set;
		}

		public string user_name {
			[CCode (cname = "hdfsBuilderSetUserName")]
			set;
		}

		public string kerb_ticket_cache_path {
			[CCode (cname = "hdfsBuilderSetKerbTicketCachePath")]
			set;
		}

		[CCode (cname = "hdfsNewBuilder")]
		public Builder ();

		[CCode (cname = "hdfsBuilderForceNewInstance")]
		public void force_new_instance ();

		[CCode (cname = "hdfsBuilderConfSetStr")]
		public void @set (string key, string? val);
	}

	[CCode (cname = "hdfsConfGetStr")]
	public int conf_get_str (string key, out string? val);

	[CCode (cname = "hdfsConfGetInt")]
	public int conf_get_int (string key, out int32 val);

	[Compact]
	[CCode (cname = "hdfsFS", has_type_id = false)]
	public class FileSystem
	{
		[Deprecated (replacement = "HDFS.FileSystem.builder_connect")]
		[CCode (cname = "hdfsConnectAsUser")]
		public FileSystem.connect_as_user (string nn, uint16 port, string? user);
		[Deprecated (replacement = "HDFS.FileSystem.builder_connect")]
		[CCode (cname = "hdfsConnect")]
		public FileSystem.connect (string nn, uint16 port);
		[Deprecated (replacement = "HDFS.FileSystem.builder_connect")]
		[CCode (cname = "hdfsConnectAsUserNewInstance")]
		public FileSystem.connect_as_user_new_instance (string nn, uint16 port, string? user);
		[Deprecated (replacement = "HDFS.FileSystem.builder_connect")]
		[CCode (cname = "hdfsConnectNewInstance")]
		public FileSystem.connect_new_instance (string nn, uint16 port);
		[CCode (cname = "hdfsBuilderConnect")]
		public FileSystem.builder_connect (HDFS.Builder bld);
		[CCode (cname = "hdfsDisconnect")]
		public int disconnect ();
		[CCode (cname = "hdfsOpenFile")]
		public HDFS.File? open_file (string path, FileOpenFlags flags, int buffer_size, short replication, int32 blocksize);
		[CCode (cname = "hdfsCloseFile")]
		public int close_file (HDFS.File file);
		[CCode (cname = "hdfsExists")]
		public bool exists (string path);
		[CCode (cname = "hdfsSeek")]
		public int seek (HDFS.File file, int64 desired_pos);
		[CCode (cname = "hdfsTell")]
		public int64 tell (HDFS.File file);
		[CCode (cname = "hdfsRead")]
		public int32 read (HDFS.File file, [CCode (array_type = "int32_t")] uint8[] buffer);
		[CCode (cname = "hdfsPread")]
		public int32 pread (HDFS.File file, int64 position, [CCode (array_type = "int32_t")] uint8[] buffer);
		[CCode (cname = "hdfsWrite")]
		public int32 write (HDFS.File file, [CCode (array_length_type = "int32_t")] uint8[] buffer);
		[CCode (cname = "hdfsFlush")]
		public int flush (HDFS.File file);
		[CCode (cname = "hdfsAvailable")]
		public int available (HDFS.File file);
		[CCode (cname = "hdfsCopy")]
		public int copy (string src, HDFS.FileSystem dst_fs, string dst);
		[CCode (cname = "hdfsMove")]
		public int move (string src, HDFS.FileSystem dst_fs, string dst);
		[CCode (cname = "hdfsDelete")]
		public int @delete (string path);
		[CCode (cname = "hdfsRename")]
		public int rename (string old_path, string new_path);
		[CCode (cname = "hdfsGetWorkingDirectory")]
		public string? get_working_directory ([CCode (array_length_type = "size_t")] uint8[] buffer);
		[CCode (cname = "hdfsSetWorkingDirectory")]
		public int set_working_directory (string path);
		[CCode (cname = "hdfsCreateDirectory")]
		public int create_directory (string path);
		[CCode (cname = "hdfsSetReplication")]
		public int set_replication (string path, int16 replication);
		[CCode (cname = "hdfsListDirectory")]
		public HDFS.FileInfo[]? list_directory (string path, int num_entries);
		[CCode (cname = "hdfsGetPathInfo")]
		public HDFS.FileInfo? get_path_info (string path);
		[CCode (cname = "hdfsGetHosts", array_null_terminated = true)]
		public string[][]? get_hosts (string path, int64 offset, int64 length);
		[CCode (cname = "hdfsGetDefaultBlockSize")]
		public int64 get_default_block_size ();
		[CCode (cname = "hdfsGetCapacity")]
		public int64 get_capacity ();
		[CCode (cname = "hdfsGetUsed")]
		public int64 get_used ();
		[CCode (cname = "hdfsUtime")]
		public int chown (string path, string? owner, string? group);
		[CCode (cname = "hdfsUtime")]
		public int chmod (string path, short mode);
		[CCode (cname = "hdfsUtime")]
		public int utime (string path, time_t mtime, time_t atime);
	}

	[CCode (cname = "hdfsFileInfo")]
	public struct FileInfo
	{
		[CCode (cname = "mKind")]
		HDFS.FileType kind;
		[CCode (cname = "mName")]
		string name;
		[CCode (cname = "mLastMod")]
		time_t last_modification;
		[CCode (cname = "mSize")]
		int32 size;
		[CCode (cname = "mReplication")]
		short replication;
		[CCode (cname = "mBlockSize")]
		int32 block_size;
		[CCode (cname = "mOwner")]
		string owner,
		[CCode (cname = "mGroup")]
		string group;
		[CCode (cname = "mPermissions")]
		short permissions;
		[CCode (cname = "mLastAccess")]
		time_t last_access;
	}
}
