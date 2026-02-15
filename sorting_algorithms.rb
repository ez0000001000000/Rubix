# Ruby Sorting Algorithms Implementation
# This file demonstrates various sorting algorithms in Ruby

class SortingAlgorithms
  # Bubble Sort - O(n^2) time complexity
  def self.bubble_sort(arr)
    n = arr.length
    (0...n).each do |i|
      swapped = false
      (0...(n - i - 1)).each do |j|
        if arr[j] > arr[j + 1]
          arr[j], arr[j + 1] = arr[j + 1], arr[j]
          swapped = true
        end
      end
      break unless swapped
    end
    arr
  end

  # Quick Sort - O(n log n) average time complexity
  def self.quick_sort(arr)
    return arr if arr.length <= 1

    pivot = arr[arr.length / 2]
    left = arr.select { |x| x < pivot }
    middle = arr.select { |x| x == pivot }
    right = arr.select { |x| x > pivot }

    quick_sort(left) + middle + quick_sort(right)
  end

  # Merge Sort - O(n log n) time complexity
  def self.merge_sort(arr)
    return arr if arr.length <= 1

    mid = arr.length / 2
    left = merge_sort(arr[0...mid])
    right = merge_sort(arr[mid..-1])

    merge(left, right)
  end

  def self.merge(left, right)
    result = []
    left_idx, right_idx = 0, 0

    while left_idx < left.length && right_idx < right.length
      if left[left_idx] <= right[right_idx]
        result << left[left_idx]
        left_idx += 1
      else
        result << right[right_idx]
        right_idx += 1
      end
    end

    result + left[left_idx..-1] + right[right_idx..-1]
  end

  # Insertion Sort - O(n^2) time complexity
  def self.insertion_sort(arr)
    (1...arr.length).each do |i|
      key = arr[i]
      j = i - 1

      while j >= 0 && arr[j] > key
        arr[j + 1] = arr[j]
        j -= 1
      end

      arr[j + 1] = key
    end
    arr
  end

  # Selection Sort - O(n^2) time complexity
  def self.selection_sort(arr)
    n = arr.length
    (0...n).each do |i|
      min_idx = i
      ((i + 1)...n).each do |j|
        min_idx = j if arr[j] < arr[min_idx]
      end

      arr[i], arr[min_idx] = arr[min_idx], arr[i] if min_idx != i
    end
    arr
  end

  # Binary Search - O(log n) time complexity
  # Assumes array is sorted
  def self.binary_search(arr, target)
    left, right = 0, arr.length - 1

    while left <= right
      mid = left + (right - left) / 2

      return mid if arr[mid] == target

      if arr[mid] < target
        left = mid + 1
      else
        right = mid - 1
      end
    end

    -1 # Not found
  end
end

# Example usage
if __FILE__ == $0
  # Test data
  unsorted_array = [64, 34, 25, 12, 22, 11, 90]
  sorted_array = [11, 12, 22, 25, 34, 64, 90]

  puts "Original array: #{unsorted_array}"

  # Test Bubble Sort
  bubble_sorted = SortingAlgorithms.bubble_sort(unsorted_array.dup)
  puts "Bubble Sort: #{bubble_sorted}"

  # Test Quick Sort
  quick_sorted = SortingAlgorithms.quick_sort(unsorted_array.dup)
  puts "Quick Sort: #{quick_sorted}"

  # Test Merge Sort
  merge_sorted = SortingAlgorithms.merge_sort(unsorted_array.dup)
  puts "Merge Sort: #{merge_sorted}"

  # Test Insertion Sort
  insertion_sorted = SortingAlgorithms.insertion_sort(unsorted_array.dup)
  puts "Insertion Sort: #{insertion_sorted}"

  # Test Selection Sort
  selection_sorted = SortingAlgorithms.selection_sort(unsorted_array.dup)
  puts "Selection Sort: #{selection_sorted}"

  # Test Binary Search
  target = 25
  index = SortingAlgorithms.binary_search(sorted_array, target)
  puts "Binary Search for #{target} in #{sorted_array}: Index #{index}"
end
