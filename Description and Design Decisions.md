Hybrid-Cloud-SSD-Filesystem
===========================
Descripton

This is a file system called CloudFS which integrates Solid State Devices(SSDs) and cloud storage (Amazon S3). This file system is built using the File System in User-Space(FUSE) toolkit.

CloudFS includes three dimensions: a core file system that leverages the properties of SSDs and cloud storage for making data placement decision, a second dimension that takes advantage of redundancy in datasets to reduce storage capacity and a third dimension that uses local caching to improve performance and reduce (cloud) costs. The SSD device will have a dedicated local file system (e.g. ext2) mounted on it while the  Cloud storage can be accessed via the Amazon S3 Interface

Design Decisions

Phase1: Building the Hybrid File system
–	Size-Based data placement
Small objects are placed on the SSD and large objects are on the cloud storage. This is because the storage costs are much lesser than transfer costs for cloud. The threshold to transfer can be set from command line during run-time.
–	Saving the attributes of the migrated file
The attributes (such as size, timestamps and permissions) of a big file that is in the cloud are stored as extended attributes of the file. This is to ensure that small, frequent operation like ls, stat do not go all the way to the Cloud as this will increase cloud costs.
–	Mapping Files to objects in cloud
Since Amazon s3 does not allow for '/' in the filename, I have replaced '/' with a '+'. As an alternative the inode numbers or the hash or any unique value could be use to name the file in cloud.

Phase2: Block-level Deduplication
If you have a lot of files that have the same or nearly the same content, you pay the price of storing the duplicate content again and again.  Deduplication is used to discover duplication among unrelated files and store identical content only once. This was done by dividing a file into segments and storing duplicate segments once.
–	Identifying the segment boundaries
Rabin Fingerprinting algorithm was used to find the segment boundaries in a clever way by looking for a pattern instead of dividing by length. This way one small addition in the beginning did not change all the segments. Then these segments were compared for duplicates.
–	Identifying the duplicated segments
A global lookup/hash table was used to store the segments in cloud and a reference count was used to keep track of the number of duplicates. Hence if reference count is >=1 we only increment the count without putting the segment in the cloud.
–	Mapping files to segments
A hidden per-file proxy file was used to keep in track of all the segments of a particular file. This was required to build back a file from segments or to delete all segments of a file, when the file was deleted.
–	Deleting segments on file deletion
While deleting the segments of a particular file, we delete it from the cloud if and only if the reference count for that particular segment is 0, (i.e. no other file contain that segment), else we only decrement the reference count.
–	Persistency of Global hash table
The contents of the Global Hash Table are written to a hidden file called .lookup and populated back from this file during re-runs.

Phase3: File-Level Caching on SSD
Frequently used files were cached on SSD to reduce cloud transfer cost and also to reduce service times as SSDs are much faster.
–	Cache replacement policy
Right now a size based replacement policy is used as bigger file transfers incur less cost, But I have also made provisions to transfer based on Least recently used or least frequently used. In the future a weight based algorithm with all these three factors will be considered.
–	Persistency of Cache contents
At mount time, CloudFS scans its cache to figure out what is contained there and build an in-memory linked list describing the contents of the cache. It is built according to the replacement algorithm, so that the items in the front are removed first.
